//go:build allowout_port

package cubevs

// Contract tests for allow_out targets pinned to an L4 port.
//
// This file only compiles behind `-tags allowout_port`: it names the fields
// and behaviour the implementation must add, so it is deliberately absent from
// the default build until then. Run it with:
//
//	go test -tags allowout_port -run TestAllowOutPortImpl ./...
//
// Contract:
//   - allowOutPolicyEntry gains `port uint16` (host order, 0 = any port).
//   - AllowOutRule gains `Port uint16` with JSON tag `port,omitempty`.
//   - A pure port entry expands to exactly one /48 row with Flags=0, Scheme=0,
//     KeyPrefixlen=48; the key port is stored via htonsPort.
//   - "IP:port" and "IP/32:port" are the same entry and the same row.
//   - A persisted snapshot keeps the port through JSON, restore and re-expand;
//     it must never widen to a /32 any-port row.
//   - mergeAllowOutWithL7 must not swallow a same-host port rule.
//   - The expanded row count, not the entry count, is what the 8192 budget
//     bounds.

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

func allowOutPortImplIP(t *testing.T, raw string) uint32 {
	t.Helper()
	ip := net.ParseIP(raw).To4()
	if ip == nil {
		t.Fatalf("bad test IP %q", raw)
	}
	return ipToUint32(ip)
}

func TestAllowOutPortImplEntryExpandsToSinglePortRow(t *testing.T) {
	ip := allowOutPortImplIP(t, "203.0.113.9")

	rows := expandAllowOutEntry(allowOutPolicyEntry{
		key:  lpmKey{Prefixlen: 32, IP: ip},
		port: 8080,
	})
	if len(rows) != 1 {
		t.Fatalf("expandAllowOutEntry returned %d rows, want 1: a plain port rule is one /48 row", len(rows))
	}
	row := rows[0]
	if row.key.Prefixlen != 48 {
		t.Fatalf("key.Prefixlen=%d, want 48", row.key.Prefixlen)
	}
	if row.key.IP != ip {
		t.Fatalf("key.IP=%#x, want %#x", row.key.IP, ip)
	}
	if row.key.Port != htonsPort(8080) {
		t.Fatalf("key.Port=%#x, want network-byte-order %#x", row.key.Port, htonsPort(8080))
	}
	if row.val.Flags != 0 {
		t.Fatalf("val.Flags=%#x, want 0 (plain L4 allow, no L7 marker)", row.val.Flags)
	}
	if row.val.Scheme != L7SchemeNone {
		t.Fatalf("val.Scheme=%d, want L7SchemeNone", row.val.Scheme)
	}
	if row.val.KeyPrefixlen != 48 {
		t.Fatalf("val.KeyPrefixlen=%d, want 48", row.val.KeyPrefixlen)
	}
}

func TestAllowOutPortImplBareAndSlash32RowsAreIdentical(t *testing.T) {
	bare, err := buildAllowOutPolicyEntries([]string{"203.0.113.9:8080"})
	if err != nil {
		t.Fatalf("buildAllowOutPolicyEntries(bare): %v", err)
	}
	slash32, err := buildAllowOutPolicyEntries([]string{"203.0.113.9/32:8080"})
	if err != nil {
		t.Fatalf("buildAllowOutPolicyEntries(/32): %v", err)
	}
	if len(bare) != 1 || len(slash32) != 1 {
		t.Fatalf("entries bare=%d slash32=%d, want 1 each", len(bare), len(slash32))
	}
	// Compare the rows, not the entries: `source` legitimately keeps the
	// caller's spelling, while the datapath-visible result must be identical.
	if !reflect.DeepEqual(expandAllowOutEntry(bare[0]), expandAllowOutEntry(slash32[0])) {
		t.Fatalf("rows differ:\n bare=%+v\n /32 =%+v",
			expandAllowOutEntry(bare[0]), expandAllowOutEntry(slash32[0]))
	}
}

func TestAllowOutPortImplAllowOutRuleJSONRoundTrip(t *testing.T) {
	rule := AllowOutRule{CIDR: "203.0.113.9/32", Port: 8080}
	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal AllowOutRule: %v", err)
	}
	if !strings.Contains(string(data), `"port":8080`) {
		t.Fatalf("serialised rule %s does not carry the port field", data)
	}
	var back AllowOutRule
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal AllowOutRule: %v", err)
	}
	if !reflect.DeepEqual(back, rule) {
		t.Fatalf("round-trip=%+v, want %+v", back, rule)
	}
}

func TestAllowOutPortImplSnapshotRestoreKeepsPort(t *testing.T) {
	snap := newEmptySnapshot(7)
	snap.AllowOut = []AllowOutRule{{CIDR: "203.0.113.9/32", Port: 8080}}

	data, err := marshalSnapshot(snap)
	if err != nil {
		t.Fatalf("marshalSnapshot: %v", err)
	}
	restored, err := unmarshalSnapshot(data)
	if err != nil {
		t.Fatalf("unmarshalSnapshot: %v", err)
	}
	if len(restored.AllowOut) != 1 || restored.AllowOut[0].Port != 8080 {
		t.Fatalf("restored AllowOut=%+v, want one rule with Port=8080", restored.AllowOut)
	}

	desired := computeEffective(restored, buildPlainDomainRuleSet(nil), 0)
	if len(desired.allowOut) != 1 {
		t.Fatalf("desired allow_out rows=%+v, want exactly one /48 row", desired.allowOut)
	}
	if got := desired.allowOut[0]; got.Prefixlen != 48 || got.Port != 8080 || got.Flags != 0 || got.Scheme != 0 {
		t.Fatalf("desired row=%+v, want {Prefixlen:48 Port:8080 Flags:0 Scheme:0}", got)
	}

	// This is the restore point the implementation must handle:
	// allowOutFromStaticMirror currently folds every /48 row into an L7
	// AllowOutRule{Ports: ...}; a plain (Flags=0) /48 row must instead become
	// AllowOutRule{Port: 8080}, or the next expand widens it to /32 any-port.
	rules, adopted := adoptAllowInputs(desired.allowOut)
	if len(adopted) != 0 {
		t.Fatalf("adopted dynamic rows=%+v, want none for a static port row", adopted)
	}
	if len(rules) != 1 {
		t.Fatalf("restored rules=%+v, want one", rules)
	}
	if rules[0].CIDR != "203.0.113.9/32" || rules[0].Port != 8080 ||
		rules[0].Flags != 0 || len(rules[0].Ports) != 0 {
		t.Fatalf("restored rule=%+v, want {CIDR:203.0.113.9/32 Port:8080 Flags:0 Ports:[]}", rules[0])
	}

	entry, err := rules[0].policyEntry()
	if err != nil {
		t.Fatalf("policyEntry: %v", err)
	}
	rows := expandAllowOutEntry(entry)
	if len(rows) != 1 {
		t.Fatalf("re-expanded rows=%+v, want exactly one", rows)
	}
	if rows[0].key.Prefixlen != 48 || rows[0].key.Port != htonsPort(8080) {
		t.Fatalf("re-expanded row=%+v, want /48 port 8080 (not /32 any-port)", rows[0])
	}
}

func TestAllowOutPortImplMergeWithL7KeepsPortRow(t *testing.T) {
	ip := allowOutPortImplIP(t, "203.0.113.9")
	l7Port := uint16(8443)

	base := []allowOutPolicyEntry{
		{key: lpmKey{Prefixlen: 32, IP: ip}},            // allow_out "203.0.113.9"
		{key: lpmKey{Prefixlen: 32, IP: ip}, port: 443}, // allow_out "203.0.113.9:443"
	}
	l7 := []allowOutPolicyEntry{{
		key:   lpmKey{Prefixlen: 32, IP: ip},
		flags: uint8(netPolicyFlagL7Required),
		ports: []l7PortEntry{{Port: htonsPort(l7Port), Scheme: L7SchemeHTTPS}},
	}}

	merged := mergeAllowOutWithL7(base, l7)

	anyPortKey := lpmKeyV3{Prefixlen: 32, IP: ip}
	plainPortKey := lpmKeyV3{Prefixlen: 48, IP: ip, Port: htonsPort(443)}
	l7Key := lpmKeyV3{Prefixlen: 48, IP: ip, Port: htonsPort(l7Port)}

	got := map[lpmKeyV3]netPolicyValueV3{}
	for _, entry := range merged {
		for _, row := range expandAllowOutEntry(entry) {
			got[row.key] = row.val
		}
	}

	for _, key := range []lpmKeyV3{anyPortKey, plainPortKey, l7Key} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing row %+v after merge (got %+v)", key, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expanded rows=%+v, want exactly the any-port, port-443 and L7 rows", got)
	}
	if v := got[anyPortKey]; v.Flags != 0 {
		t.Fatalf("any-port row flags=%#x, want 0", v.Flags)
	}
	if v := got[plainPortKey]; v.Flags != 0 || v.Scheme != L7SchemeNone {
		t.Fatalf("port-443 row value=%+v, want plain Flags=0 Scheme=0", v)
	}
	if v := got[l7Key]; v.Flags&uint8(netPolicyFlagL7Required) == 0 || v.Scheme != L7SchemeHTTPS {
		t.Fatalf("L7 row value=%+v, want L7Required + HTTPS", v)
	}
}

func TestAllowOutPortImplBudgetBoundary(t *testing.T) {
	targets := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("198.51.%d.%d:8080", (i>>8)&0xff, i&0xff))
		}
		return out
	}

	for _, tc := range []struct {
		name    string
		count   int
		wantErr bool
	}{
		{name: "8192 rows accepted", count: 8192},
		{name: "8193 rows rejected", count: 8193, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := buildAllowOutPolicyEntries(targets(tc.count))
			if err != nil {
				t.Fatalf("buildAllowOutPolicyEntries: %v", err)
			}
			if got := expandedAllowOutEntryCount(entries); got != tc.count {
				t.Fatalf("expandedAllowOutEntryCount=%d, want %d", got, tc.count)
			}
			err = validateNetPolicyPlan(&netPolicyPlan{allowOutEntries: entries})
			if tc.wantErr && err == nil {
				t.Fatalf("validateNetPolicyPlan accepted %d rows; max is %d", tc.count, maxNetPolicyEntries)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateNetPolicyPlan rejected %d rows: %v", tc.count, err)
			}
		})
	}
}
