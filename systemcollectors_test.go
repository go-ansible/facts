package facts

import (
	"reflect"
	"testing"
)

// Every expectation here comes from real's own collectors, not from
// this port: the Darwin values were measured from ansible-core 2.21.4
// on this machine, and the Linux-only ones are traced through the
// Python line by line, because no Darwin host can produce them.

func TestApparmorFacts(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"enabled", "enabled"},
		{"disabled", "disabled"},
		// Measured on this machine: real reports the fact even where
		// the path cannot exist.
		{"", "disabled"},
	} {
		got := apparmorFacts(map[string]string{"apparmor_status": tc.in})
		if got["status"] != tc.want {
			t.Errorf("apparmor_status %q: status = %v, want %v", tc.in, got["status"], tc.want)
		}
	}
}

func TestSelinuxFactsIsTheMissingLibraryBranch(t *testing.T) {
	sel, present := selinuxFacts()
	if present {
		t.Error("selinux_python_present = true; this port has no Python binding to find")
	}
	// The exact string real emits, measured.
	if sel["status"] != "Missing selinux Python library" {
		t.Errorf("status = %v", sel["status"])
	}
	// And nothing else: real's other keys (mode, type, policyvers,
	// config_mode) exist only in the branch where the binding loaded.
	if len(sel) != 1 {
		t.Errorf("selinux = %v, want only status", sel)
	}
}

func TestVirtualFactsAreTheGenericCollector(t *testing.T) {
	// Measured: ansible-core on this Mac reports "", "", [], []. There
	// is no darwin.py under facts/virtual/, so this is the generic
	// base class and not a property of this host being bare metal.
	want := map[string]any{
		"virtualization_type":       "",
		"virtualization_role":       "",
		"virtualization_tech_guest": []any{},
		"virtualization_tech_host":  []any{},
	}
	if got := virtualFacts(); !reflect.DeepEqual(got, want) {
		t.Errorf("virtualFacts() = %#v, want %#v", got, want)
	}
}

func TestCapsFactsWithoutCapsh(t *testing.T) {
	// Measured on this machine: both are the STRING "N/A", not a list.
	for _, rc := range []string{"-1", "1", "127", ""} {
		caps, enforced := capsFacts(map[string]string{"caps_rc": rc})
		if caps != "N/A" || enforced != "N/A" {
			t.Errorf("caps_rc=%q: got %v/%v, want N/A/N/A", rc, caps, enforced)
		}
	}
}

func TestCapsFactsWithCapsh(t *testing.T) {
	for _, tc := range []struct {
		name, line   string
		wantCaps     any
		wantEnforced string
	}{
		{
			// MEASURED under sudo on Linux: root gets "Current: =ep",
			// the one spelling real special-cases, and it reports
			// enforcement OFF with no list.
			name: "=ep as root", line: "Current: =ep",
			wantCaps: []any{}, wantEnforced: "False",
		},
		{
			// MEASURED. What an ordinary user actually gets: capsh
			// prints "Current: =" with nothing after the sign. Real
			// reports a list holding one EMPTY string, because
			// "".split(",") is [""] and not []. This is the common
			// case on Linux and none of the invented lines below
			// covered it.
			name: "unprivileged", line: "Current: =",
			wantCaps: []any{""}, wantEnforced: "True",
		},
		{
			// HAND-TRACED, not measured: no host here prints this.
			// Anything else is "True" -- and real then takes
			// split('=')[1], which for this line is the FLAGS, not the
			// capabilities. That reads oddly and it is what real
			// reports; a port that "fixed" it would diverge.
			name: "bounded set", line: "Current: cap_chown,cap_dac_override=eip",
			wantCaps: []any{"eip"}, wantEnforced: "True",
		},
		{
			// HAND-TRACED.
			name: "modern spelling", line: "Current: =ep cap_chown-ep",
			wantCaps: []any{"ep cap_chown-ep"}, wantEnforced: "True",
		},
		{
			// HAND-TRACED. TWO '=' signs, which is the only case that tells
			// split('=')[1] apart from "everything after the first
			// '='". A Cut here would keep "=i" and report one
			// capability too many. Without this line the three cases
			// above passed with either reading.
			name: "two equals signs", line: "Current: cap_chown,cap_setuid=ep cap_net_bind_service=i",
			wantCaps: []any{"ep cap_net_bind_service"}, wantEnforced: "True",
		},
		{
			// HAND-TRACED. capsh exited 0 but printed no Current: line. Real's
			// seed value survives, and it is spelt NA, not N/A.
			name: "no Current line", line: "",
			wantCaps: []any{}, wantEnforced: "NA",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps, enforced := capsFacts(map[string]string{"caps_rc": "0", "caps_current": tc.line})
			if !reflect.DeepEqual(caps, tc.wantCaps) {
				t.Errorf("caps = %#v, want %#v", caps, tc.wantCaps)
			}
			if enforced != tc.wantEnforced {
				t.Errorf("enforced = %v, want %v", enforced, tc.wantEnforced)
			}
		})
	}
}

func TestLsbFactsEmptyOnAHostWithoutLsb(t *testing.T) {
	// Measured on this machine: real reports an empty dict, not the
	// absence of the fact.
	got := lsbFacts(map[string]string{
		"lsb_id": "0", "lsb_release": "0", "lsb_description": "0", "lsb_codename": "0",
	})
	if len(got) != 0 {
		t.Errorf("lsb = %#v, want {}", got)
	}
}

func TestLsbFacts(t *testing.T) {
	got := lsbFacts(map[string]string{
		"lsb_id":          "1Ubuntu",
		"lsb_release":     "122.04",
		"lsb_description": "1Ubuntu 22.04.3 LTS",
		"lsb_codename":    "1jammy",
	})
	want := map[string]any{
		"id": "Ubuntu", "release": "22.04",
		"description": "Ubuntu 22.04.3 LTS", "codename": "jammy",
		"major_release": "22",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lsb = %#v, want %#v", got, want)
	}
}

func TestLsbFactsKeepsALabelThatPrintedNothing(t *testing.T) {
	// Real stores lsb_facts['codename'] = '' for a label that appeared
	// with an empty value, and stores no key at all for one that never
	// appeared. Collapsing the two would drop a key real reports.
	got := lsbFacts(map[string]string{
		"lsb_id": "1Ubuntu", "lsb_release": "0", "lsb_description": "0", "lsb_codename": "1",
	})
	want := map[string]any{"id": "Ubuntu", "codename": ""}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lsb = %#v, want %#v", got, want)
	}
	// No release label, so no major_release -- real guards on the key.
	if _, ok := got["major_release"]; ok {
		t.Error("major_release derived from an absent release")
	}
}

func TestLsbFactsStripsQuotesAfterDerivingMajor(t *testing.T) {
	// Real computes major_release from the raw value and strips quotes
	// from every value afterwards, major_release included -- so the
	// opening quote is removed by the strip, not by the split.
	got := lsbFacts(map[string]string{
		"lsb_id": "0", "lsb_release": `1"22.04"`, "lsb_description": "0", "lsb_codename": "0",
	})
	if got["release"] != "22.04" {
		t.Errorf("release = %v, want 22.04", got["release"])
	}
	if got["major_release"] != "22" {
		t.Errorf("major_release = %v, want 22", got["major_release"])
	}
}

func TestAssembleReportsEverySecurityFact(t *testing.T) {
	// The whole point of this increment: real names all eight of these
	// on every host, so assemble must too even when the probe found
	// nothing to report.
	out := assemble(map[string]string{}, "", nil)
	for _, k := range []string{
		"apparmor", "lsb", "selinux", "selinux_python_present",
		"system_capabilities", "system_capabilities_enforced",
		"virtualization_type", "virtualization_role",
		"virtualization_tech_guest", "virtualization_tech_host",
	} {
		if _, ok := out[k]; !ok {
			t.Errorf("assemble did not report %q", k)
		}
	}
}
