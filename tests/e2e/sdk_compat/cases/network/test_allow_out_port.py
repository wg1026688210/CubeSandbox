# Copyright (c) 2026 Tencent Inc.
# SPDX-License-Identifier: Apache-2.0

"""allow_out with an IPv4 port qualifier (``IP:port`` / ``IP/32:port``).

The policy under test is a plain L3/L4 allow pinned to one port:

    allow_out = ["<ip>:<port>"], deny_out = ["0.0.0.0/0"]

Both a bare IP and its /32 form must mean the same thing, only the named port
is reachable on that host, and every invalid shape is rejected with 400 while
leaving the previous policy in place.

Target selection: the default targets are two ports that are open on the same
public IP (8.8.8.8:53 DNS-over-TCP and 8.8.8.8:443 DoH). Both being open before
the policy is what makes the blocked-port probe a policy verdict rather than an
unreachable-host artifact. Override them for air-gapped environments:

    SDK_E2E_PORT_POLICY_TARGET_IP
    SDK_E2E_PORT_POLICY_ALLOWED_PORT
    SDK_E2E_PORT_POLICY_BLOCKED_PORT
"""

from __future__ import annotations

import os

import pytest
from cubesandbox._exceptions import ApiError
from framework.capabilities import (
    NETWORK_ALLOW_DENY,
    NETWORK_DYNAMIC_UPDATE,
    PAUSE_RESUME,
    ROLLBACK_CLONE,
)
from framework.lifecycle import (
    wait_until_data_plane_ready,
    wait_until_paused,
    wait_until_running,
)
from framework.network_probe import (
    assert_tcp_blocked,
    assert_tcp_reachable,
    tcp_probe_command,
)

TARGET_IP = os.environ.get("SDK_E2E_PORT_POLICY_TARGET_IP", "8.8.8.8")
ALLOWED_PORT = int(os.environ.get("SDK_E2E_PORT_POLICY_ALLOWED_PORT", "53"))
BLOCKED_PORT = int(os.environ.get("SDK_E2E_PORT_POLICY_BLOCKED_PORT", "443"))

DENY_ALL = "0.0.0.0/0"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.sdk_compat,
    pytest.mark.network,
    pytest.mark.p1,
    pytest.mark.requires_internet,
    pytest.mark.requires_capability(NETWORK_ALLOW_DENY),
]


def _port_target(port: int, *, slash32: bool = False) -> str:
    host = f"{TARGET_IP}/32" if slash32 else TARGET_IP
    return f"{host}:{port}"


def _policy(allow_out: list[str], deny_out: list[str] | None = None) -> dict:
    return {
        "allow_internet_access": False,
        "allow_out": list(allow_out),
        "deny_out": list(deny_out or [DENY_ALL]),
    }


def _probe(sandbox, sdk_e2e_config, port: int):
    return sandbox.run_command(
        tcp_probe_command(
            TARGET_IP,
            port=port,
            timeout=sdk_e2e_config.network_probe_timeout,
        ),
        timeout=sdk_e2e_config.command_timeout,
    )


def _assert_only_port_allowed(sandbox, sdk_e2e_config) -> None:
    assert_tcp_reachable(
        _probe(sandbox, sdk_e2e_config, ALLOWED_PORT),
        TARGET_IP,
        ALLOWED_PORT,
    )
    assert_tcp_blocked(
        _probe(sandbox, sdk_e2e_config, BLOCKED_PORT),
        TARGET_IP,
        BLOCKED_PORT,
    )


@pytest.mark.sandbox_create_options(
    allow_internet_access=False,
    network={"allow_out": [_port_target(ALLOWED_PORT)], "deny_out": [DENY_ALL]},
)
def test_allow_out_ip_port_permits_only_that_port(sdk_sandbox, sdk_e2e_config):
    """``IP:port`` keeps the named port and withdraws every other port."""
    _assert_only_port_allowed(sdk_sandbox, sdk_e2e_config)


@pytest.mark.sandbox_create_options(
    allow_internet_access=False,
    network={
        "allow_out": [_port_target(ALLOWED_PORT, slash32=True)],
        "deny_out": [DENY_ALL],
    },
)
def test_allow_out_slash32_port_is_equivalent(sdk_sandbox, sdk_e2e_config):
    """``IP/32:port`` is the same rule as ``IP:port``, not a wider CIDR."""
    _assert_only_port_allowed(sdk_sandbox, sdk_e2e_config)


@pytest.mark.requires_capability(NETWORK_DYNAMIC_UPDATE)
@pytest.mark.sandbox_create_options(
    allow_internet_access=False,
    network={"allow_out": [TARGET_IP], "deny_out": [DENY_ALL]},
)
def test_update_narrows_any_port_allow_to_single_port(sdk_sandbox, sdk_e2e_config):
    """An update replaces the any-port allow with a single-port rule."""
    assert_tcp_reachable(
        _probe(sdk_sandbox, sdk_e2e_config, BLOCKED_PORT),
        TARGET_IP,
        BLOCKED_PORT,
    )

    sdk_sandbox.update_network(network=_policy([_port_target(ALLOWED_PORT)]))

    _assert_only_port_allowed(sdk_sandbox, sdk_e2e_config)


# Open contract question, kept skipped rather than silently passing or
# contradicting INVALID_ALLOW_OUT above: the agreed semantics reject every
# `prefix<32 + port` target, yet the task also asks for `10.0.0.0/24:443` to be
# accepted at create as 256 expanded /48 rows. The two cannot both hold.
@pytest.mark.skip(
    reason=(
        "semantics undecided: `prefix<32 + port` is rejected by the agreed "
        "contract and INVALID_ALLOW_OUT, but this case expects a /24:port to "
        "expand to 256 /48 rows at create; also 10.0.0.0/24 is RFC1918 "
        "always-deny with no reachable endpoint. Resolve before enabling."
    )
)
def test_allow_out_cidr_port_expands_within_budget():
    """Explicit gap, not a pass: /24+port acceptance contradicts the contract."""


INVALID_ALLOW_OUT = [
    ("cidr_8_with_port", "10.0.0.0/8:443"),
    ("cidr_24_with_port", "10.0.0.0/24:443"),
    ("domain_with_port", "example.com:443"),
    ("wildcard_domain_with_port", "*.example.com:443"),
    ("ipv6_literal", "2001:db8::1"),
    ("ipv6_cidr", "2001:db8::/64"),
    ("port_zero", f"{TARGET_IP}:0"),
    ("port_above_65535", f"{TARGET_IP}:65536"),
    ("port_range", f"{TARGET_IP}:{ALLOWED_PORT}-{BLOCKED_PORT}"),
    ("comma_separated_ports", f"{TARGET_IP}:{ALLOWED_PORT},{BLOCKED_PORT}"),
]

INVALID_DENY_OUT = [
    ("deny_bare_port", f"{TARGET_IP}:{BLOCKED_PORT}"),
    ("deny_slash32_port", f"{TARGET_IP}/32:{BLOCKED_PORT}"),
]


@pytest.mark.requires_capability(NETWORK_DYNAMIC_UPDATE)
@pytest.mark.sandbox_create_options(
    allow_internet_access=False,
    network={"allow_out": [_port_target(ALLOWED_PORT)], "deny_out": [DENY_ALL]},
)
def test_invalid_port_targets_rejected_and_policy_unchanged(
    sdk_sandbox,
    sdk_e2e_config,
):
    """Every unsupported port shape answers 400 without changing the policy.

    A 500 here means the control plane let the target through to the node; an
    accepted update means a typo silently rewrote the egress policy.
    """
    for name, target in INVALID_ALLOW_OUT:
        with pytest.raises(ApiError) as exc:
            sdk_sandbox.update_network(network=_policy([target]))
        assert exc.value.status_code == 400, (
            f"allow_out[{name}]={target!r} should be rejected with HTTP 400, "
            f"got {exc.value.status_code}: {exc.value}"
        )

        # The rejected request must not have partially replaced the policy.
        _assert_only_port_allowed(sdk_sandbox, sdk_e2e_config)

    for name, target in INVALID_DENY_OUT:
        with pytest.raises(ApiError) as exc:
            sdk_sandbox.update_network(
                network=_policy([_port_target(ALLOWED_PORT)], deny_out=[target])
            )
        assert exc.value.status_code == 400, (
            f"deny_out[{name}]={target!r} should be rejected with HTTP 400, "
            f"got {exc.value.status_code}: {exc.value}"
        )

        _assert_only_port_allowed(sdk_sandbox, sdk_e2e_config)


@pytest.mark.requires_capability(PAUSE_RESUME)
@pytest.mark.sandbox_create_options(
    allow_internet_access=False,
    network={"allow_out": [_port_target(ALLOWED_PORT)], "deny_out": [DENY_ALL]},
)
def test_port_policy_survives_pause_resume(sdk_sandbox, sdk_e2e_config):
    """Resume restores the single-port policy, not an any-port one."""
    sdk_sandbox.pause(timeout=sdk_e2e_config.default_timeout)
    wait_until_paused(sdk_sandbox, timeout=sdk_e2e_config.default_timeout)

    resumed = sdk_sandbox.resume_or_connect(timeout=sdk_e2e_config.default_timeout)
    try:
        wait_until_running(resumed, timeout=sdk_e2e_config.default_timeout)
        wait_until_data_plane_ready(
            resumed,
            timeout=sdk_e2e_config.default_timeout,
            command_timeout=sdk_e2e_config.command_timeout,
        )
        _assert_only_port_allowed(resumed, sdk_e2e_config)
    finally:
        resumed.close()


@pytest.mark.requires_capability(ROLLBACK_CLONE)
@pytest.mark.requires_capability(NETWORK_DYNAMIC_UPDATE)
@pytest.mark.sandbox_create_options(
    allow_internet_access=False,
    network={"allow_out": [TARGET_IP], "deny_out": [DENY_ALL]},
)
def test_clone_after_port_update_inherits_new_policy(sdk_sandbox, sdk_e2e_config):
    """A clone created after the update carries the single-port policy."""
    sdk_sandbox.update_network(network=_policy([_port_target(ALLOWED_PORT)]))

    clones = sdk_sandbox.clone(1)
    try:
        _assert_only_port_allowed(clones[0], sdk_e2e_config)
    finally:
        for clone in clones:
            clone.kill()
