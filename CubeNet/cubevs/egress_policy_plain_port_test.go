package cubevs

import "testing"

// TestClassifyEgressFlowPlainPortRow exercises the exact row a port-pinned
// allow_out emits: one /48 key with Flags=0 and Scheme=0. The plain L4 allow
// must match TCP on that port, stay protocol-agnostic (UDP/ICMP also SNAT), and
// not leak to other ports — where deny_out then rejects.
func TestClassifyEgressFlowPlainPortRow(t *testing.T) {
	env := loadEgressPolicyTestEnv(t)
	ifindex := uint32(160)
	allowInner, denyInner := env.attachInnerMaps(t, ifindex)

	daddr := mustParseCIDRForTest(t, "192.0.2.30").IP
	dport := htonsPort(8080)
	allowKey := lpmKeyV3{Prefixlen: 48, IP: daddr, Port: dport}
	allowValue := netPolicyValueV3{KeyPrefixlen: 48}
	if err := allowInner.Put(&allowKey, &allowValue); err != nil {
		t.Fatalf("insert plain port allow rule: %v", err)
	}

	denyAll := mustParseCIDRForTest(t, "0.0.0.0/0")
	denyValue := uint32(1)
	if err := denyInner.Put(&denyAll, &denyValue); err != nil {
		t.Fatalf("insert deny-all rule: %v", err)
	}

	if got := runEgressPolicyCase(t, env.program, ifindex, daddr, dport); got != flowVerdictSNAT {
		t.Fatalf("TCP on allowed port verdict=%d, want FLOW_SNAT", got)
	}
	if got := runEgressPolicyCase(t, env.program, ifindex, daddr, htonsPort(443)); got != flowVerdictReject {
		t.Fatalf("TCP on other port verdict=%d, want FLOW_REJECT", got)
	}
	if got := runEgressPolicyCaseProto(t, env.program, ifindex, daddr, dport, ipprotoUDP); got != flowVerdictSNAT {
		t.Fatalf("UDP on allowed port verdict=%d, want FLOW_SNAT", got)
	}
	if got := runEgressPolicyCaseProto(t, env.program, ifindex, daddr, dport, ipprotoICMP); got != flowVerdictSNAT {
		t.Fatalf("ICMP on allowed port verdict=%d, want FLOW_SNAT", got)
	}
}
