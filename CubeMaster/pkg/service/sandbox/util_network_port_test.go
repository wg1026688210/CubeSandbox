// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package sandbox

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/errorcode"
	"github.com/tencentcloud/CubeSandbox/CubeMaster/pkg/service/sandbox/types"
)

// TDD spec for the control-plane egress validation. Master must reject the
// same target shapes CubeVS rejects, so an invalid update answers 400 instead
// of reaching the node and surfacing as a 500.
//
// Semantics:
//   - allowOut accepts "1.2.3.4:<port>" and "1.2.3.4/32:<port>"; a missing port
//     still means every port.
//   - A port on a prefix < 32 is rejected (no CIDR+port row exists).
//   - Ports are a single value in [1, 65535]: no 0, no 65536, no ranges/lists.
//   - Domains with a port are rejected; domain ports belong to L7 rules.
//   - IPv6 is rejected in both allowOut and denyOut.
//   - denyOut stays IP-only, so any denyOut port is rejected.

func TestValidateCubeNetworkConfigAcceptsIPv4PortAllowOut(t *testing.T) {
	for _, target := range []string{
		"1.2.3.4:8080",
		"1.2.3.4/32:8080",
		"1.2.3.4:1",
		"1.2.3.4:65535",
		"1.2.3.4",
		"10.0.0.0/8",
		"example.com",
		"*.example.com",
	} {
		t.Run(target, func(t *testing.T) {
			err := validateCubeNetworkConfig(&types.CubeNetworkConfig{
				AllowOut: []string{target},
			})
			assert.NoError(t, err, "allowOut target %q should be accepted", target)
		})
	}
}

func TestValidateCubeNetworkConfigRejectsInvalidAllowOutPort(t *testing.T) {
	for _, target := range []string{
		"10.0.0.0/8:443",
		"1.2.3.0/24:443",
		"1.2.3.4/33:443",
		"1.2.3.4:0",
		"1.2.3.4:65536",
		"1.2.3.4:80-90",
		"1.2.3.4:80,443",
		"1.2.3.4:",
		"example.com:443",
		"*.example.com:443",
		"2001:db8::1",
		"2001:db8::/64",
	} {
		t.Run(target, func(t *testing.T) {
			err := validateCubeNetworkConfig(&types.CubeNetworkConfig{
				AllowOut: []string{target},
			})
			assert.Error(t, err, "allowOut target %q must be rejected", target)
		})
	}
}

func TestValidateCubeNetworkConfigRejectsDenyOutPort(t *testing.T) {
	for _, target := range []string{
		"1.2.3.4:443",
		"1.2.3.4/32:443",
	} {
		t.Run(target, func(t *testing.T) {
			err := validateCubeNetworkConfig(&types.CubeNetworkConfig{
				DenyOut: []string{target},
			})
			assert.Error(t, err, "denyOut target %q must be rejected; deny_out is IP-only", target)
		})
	}
}

func TestValidateCubeNetworkConfigRejectsIPv6DenyOut(t *testing.T) {
	for _, target := range []string{
		"2001:db8::1",
		"2001:db8::/64",
	} {
		t.Run(target, func(t *testing.T) {
			err := validateCubeNetworkConfig(&types.CubeNetworkConfig{
				DenyOut: []string{target},
			})
			assert.Error(t, err, "denyOut target %q must be rejected", target)
		})
	}
}

// TestUpdateNetworkRejectsCIDRPortAtServiceBoundary drives the real handler
// entry point, not just the validator: the target must answer a parameter
// error before any sandbox id resolution or node round-trip. A blank-but-
// non-empty id makes the pre-validation path deterministic once the check is
// implemented (it resolves to NotFound instead of touching the cluster), so a
// regression that moves validation after id resolution still fails here.
func TestUpdateNetworkRejectsCIDRPortAtServiceBoundary(t *testing.T) {
	rsp := UpdateNetwork(context.Background(), &types.UpdateNetworkRequest{
		RequestID: "req-update-network-invalid-cidr-port",
		SandboxID: " ",
		CubeNetworkConfig: &types.CubeNetworkConfig{
			AllowOut: []string{"10.0.0.0/8:443"},
		},
	})

	assert.NotNil(t, rsp.Ret)
	assert.Equal(t, int(errorcode.ErrorCode_MasterParamsError), rsp.Ret.RetCode,
		"update_network must reject a CIDR+port target with a parameter error, got %+v", rsp.Ret)
}
