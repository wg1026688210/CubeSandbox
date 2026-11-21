package cubevs

import (
	"fmt"
	"testing"
)

// TDD spec for allow_out targets that pin an L4 port.
//
// Target semantics:
//   - "1.2.3.4:8080" and "1.2.3.4/32:8080" both mean host 1.2.3.4, TCP port 8080.
//   - A missing port ("1.2.3.4", "1.2.3.4/32") means every port (unchanged).
//   - Only a single port in [1, 65535] is accepted.
//   - A port on a prefix < 32 ("10.0.0.0/8:443") is rejected: the datapath only
//     compares the port at prefixlen 48, so there is no "CIDR + port" row.
//   - Domains (including domain:port) never carry a port; those go to L7 rules.
//   - IPv6 is rejected everywhere (allow and deny).
//   - deny_out stays IP-only.
//
// These tests call only functions that exist today. Row-level assertions that
// need the not-yet-existing port field (single /48 row, Flags=0, Scheme=0,
// KeyPrefixlen=48) are listed in the runbook instead of written here.

func TestSplitAllowOutTargetsAcceptsIPv4Port(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "bare ip", target: "1.2.3.4:8080"},
		{name: "slash 32", target: "1.2.3.4/32:8080"},
		{name: "surrounding spaces", target: " 1.2.3.4:8080 "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidrs, domains, err := splitAllowOutTargets([]string{tt.target})
			if err != nil {
				t.Fatalf("splitAllowOutTargets(%q) returned error: %v; want it accepted as an IPv4 target", tt.target, err)
			}
			if len(domains) != 0 {
				t.Fatalf("domains=%v, want none: a port-qualified IPv4 literal is not a domain", domains)
			}
			if len(cidrs) != 1 {
				t.Fatalf("cidrs=%v, want exactly one target", cidrs)
			}
		})
	}
}

func TestSplitAllowOutTargetsKeepsAnyPortAndPortTargets(t *testing.T) {
	cidrs, domains, err := splitAllowOutTargets([]string{"1.2.3.4", "1.2.3.4:8080"})
	if err != nil {
		t.Fatalf("splitAllowOutTargets returned error: %v; any-port and port-pinned targets must coexist", err)
	}
	if len(domains) != 0 {
		t.Fatalf("domains=%v, want none", domains)
	}
	if len(cidrs) != 2 {
		t.Fatalf("cidrs=%v, want both the any-port and the port-pinned target", cidrs)
	}
}

func TestSplitAllowOutTargetsRejectsUnsupportedPortTargets(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "prefix 8 with port", target: "10.0.0.0/8:443"},
		{name: "prefix 24 with port", target: "1.2.3.0/24:443"},
		{name: "prefix 33 with port", target: "1.2.3.4/33:443"},
		{name: "port zero", target: "1.2.3.4:0"},
		{name: "port above 65535", target: "1.2.3.4:65536"},
		{name: "port range", target: "1.2.3.4:80-90"},
		{name: "comma separated ports", target: "1.2.3.4:80,443"},
		{name: "empty port", target: "1.2.3.4:"},
		{name: "domain with port", target: "example.com:443"},
		{name: "wildcard domain with port", target: "*.example.com:443"},
		{name: "ipv6 literal", target: "2001:db8::1"},
		{name: "ipv6 cidr", target: "2001:db8::/64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := splitAllowOutTargets([]string{tt.target}); err == nil {
				t.Fatalf("splitAllowOutTargets(%q) returned nil error; want rejected", tt.target)
			}
		})
	}
}

func TestBuildDenyOutPolicyEntriesRejectsPortAndIPv6(t *testing.T) {
	for _, target := range []string{
		"1.2.3.4:443",
		"1.2.3.4/32:443",
		"2001:db8::1",
		"2001:db8::/64",
	} {
		t.Run(target, func(t *testing.T) {
			if _, err := buildDenyOutPolicyEntries([]string{target}); err == nil {
				t.Fatalf("buildDenyOutPolicyEntries(%q) returned nil error; deny_out is IP-only", target)
			}
		})
	}
}

func TestBuildAllowOutPolicyEntriesCountsEachPortTargetAsOneEntry(t *testing.T) {
	tests := []struct {
		name        string
		targets     []string
		wantEntries int
	}{
		{
			name:        "bare ip with port",
			targets:     []string{"1.2.3.4:8080"},
			wantEntries: 1,
		},
		{
			name:        "slash 32 with port",
			targets:     []string{"1.2.3.4/32:8080"},
			wantEntries: 1,
		},
		{
			name:        "any-port and port-pinned coexist",
			targets:     []string{"1.2.3.4", "1.2.3.4:8080"},
			wantEntries: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := buildAllowOutPolicyEntries(tt.targets)
			if err != nil {
				t.Fatalf("buildAllowOutPolicyEntries(%v) returned error: %v", tt.targets, err)
			}
			if len(entries) != tt.wantEntries {
				t.Fatalf("entries=%d, want %d", len(entries), tt.wantEntries)
			}
			// A plain port rule occupies exactly one allow_out_v3 row: the
			// datapath compares the port at prefixlen 48, with no L7 scheme.
			if got := expandedAllowOutEntryCount(entries); got != tt.wantEntries {
				t.Fatalf("expandedAllowOutEntryCount=%d, want %d; each plain port target must cost one row", got, tt.wantEntries)
			}
		})
	}
}

// TestBuildAllowOutPolicyEntriesDeduplicatesEquivalentPortTargets: the bare and
// /32 spellings name the same (host, port) pair, so they must fold into one
// entry and cost one row. Emitting two would double-charge the budget and make
// the dedup depend on which spelling the client happened to send.
func TestBuildAllowOutPolicyEntriesDeduplicatesEquivalentPortTargets(t *testing.T) {
	targets := []string{"1.2.3.4:8080", "1.2.3.4/32:8080"}

	entries, err := buildAllowOutPolicyEntries(targets)
	if err != nil {
		t.Fatalf("buildAllowOutPolicyEntries(%v) returned error: %v", targets, err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1: %q and %q are the same host:port", len(entries), targets[0], targets[1])
	}
	if got := expandedAllowOutEntryCount(entries); got != 1 {
		t.Fatalf("expandedAllowOutEntryCount=%d, want 1", got)
	}
}

// TestPortAllowOutEntriesAcceptExactBudget pins both sides of the boundary:
// exactly maxNetPolicyEntries port rows must pass, one more must reject the
// whole plan. A strict comparison off by one here silently rejects a valid
// policy or lets an oversized one half-populate the LPM trie.
func TestPortAllowOutEntriesAcceptExactBudget(t *testing.T) {
	portTargets := func(n int) []string {
		targets := make([]string, 0, n)
		for i := 0; i < n; i++ {
			targets = append(targets, fmt.Sprintf("198.51.%d.%d:8080", (i>>8)&0xff, i&0xff))
		}
		return targets
	}

	for _, tc := range []struct {
		name    string
		count   int
		wantErr bool
	}{
		{name: "exactly max entries", count: maxNetPolicyEntries},
		{name: "one over max entries", count: maxNetPolicyEntries + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := buildAllowOutPolicyEntries(portTargets(tc.count))
			if err != nil {
				t.Fatalf("buildAllowOutPolicyEntries(%d targets) returned error: %v", tc.count, err)
			}
			if got := expandedAllowOutEntryCount(entries); got != tc.count {
				t.Fatalf("expandedAllowOutEntryCount=%d, want %d", got, tc.count)
			}
			err = validateNetPolicyPlan(&netPolicyPlan{allowOutEntries: entries})
			if tc.wantErr && err == nil {
				t.Fatalf("validateNetPolicyPlan accepted %d port entries; max is %d", tc.count, maxNetPolicyEntries)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateNetPolicyPlan rejected %d port entries, want accepted: %v", tc.count, err)
			}
		})
	}
}

func TestPortAllowOutEntriesAreSubjectToThePolicyBudget(t *testing.T) {
	// maxNetPolicyEntries+1 distinct port-pinned targets must be rejected as a
	// whole. Truncating would silently widen or narrow the caller's policy.
	targets := make([]string, 0, maxNetPolicyEntries+1)
	for i := 0; i <= maxNetPolicyEntries; i++ {
		targets = append(targets, fmt.Sprintf("198.51.%d.%d:8080", (i>>8)&0xff, i&0xff))
	}

	entries, err := buildAllowOutPolicyEntries(targets)
	if err != nil {
		t.Fatalf("buildAllowOutPolicyEntries returned error: %v", err)
	}
	plan := &netPolicyPlan{allowOutEntries: entries}
	if err := validateNetPolicyPlan(plan); err == nil {
		t.Fatalf("validateNetPolicyPlan accepted %d port entries; max is %d", len(entries), maxNetPolicyEntries)
	}
}
