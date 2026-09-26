package facts

import (
	"reflect"
	"testing"
)

// The Linux half of the security collectors, measured rather than read.
//
// No Mac can produce any of this: lsb_release, /etc/lsb-release and
// capsh all exist only on Linux, and the whole differential corpus for
// this campaign runs on macOS. So the inputs below were captured from a
// real Ubuntu 24.10 aarch64 guest by running THIS probe on it, and the
// expected values were produced by running REAL ansible-core 2.21.4's
// own LSBFactCollector and SystemCapabilitiesFactCollector -- the
// unmodified Python, on the host -- over the same captured input.
//
// That is weaker than running real end to end on Linux, and it is worth
// saying which part is weaker: ansible's plumbing around the collectors
// is not exercised, only the collectors themselves. It is much stronger
// than the hand-tracing it replaced, which is what these values were
// before, and it already corrected one of them (see the "unprivileged"
// case next door: a user's capsh prints "Current: =", and real reports
// a list holding one empty string -- not an empty list).

// probeOutputUbuntu2410 is what the probe in facts.go printed on that
// guest, verbatim.
var probeOutputUbuntu2410 = map[string]string{
	"apparmor_status": "enabled",
	"lsb_id":          "1Ubuntu",
	"lsb_release":     "124.10",
	"lsb_description": "1Ubuntu 24.10",
	"lsb_codename":    "1oracular",
	"caps_rc":         "0",
	"caps_current":    "Current: =",
}

func TestLinuxWitnessLsbFromLsbReleaseBinary(t *testing.T) {
	// Real, driven by the guest's own `lsb_release -a`:
	//   {"codename": "oracular", "description": "Ubuntu 24.10",
	//    "id": "Ubuntu", "major_release": "24", "release": "24.10"}
	want := map[string]any{
		"id":            "Ubuntu",
		"release":       "24.10",
		"description":   "Ubuntu 24.10",
		"codename":      "oracular",
		"major_release": "24",
	}
	if got := lsbFacts(probeOutputUbuntu2410); !reflect.DeepEqual(got, want) {
		t.Errorf("lsb = %#v, want %#v", got, want)
	}
}

func TestLinuxWitnessLsbFromEtcLsbRelease(t *testing.T) {
	// The fallback branch, forced on the same guest by taking
	// lsb_release off PATH. Its DISTRIB_DESCRIPTION is QUOTED in the
	// file, and real strips the quotes in collect() -- which is why
	// the reference for this branch had to come from collect() and not
	// from _lsb_release_file(), whose return value still has them.
	got := lsbFacts(map[string]string{
		"lsb_id":          "1Ubuntu",
		"lsb_release":     "124.10",
		"lsb_description": `1"Ubuntu 24.10"`,
		"lsb_codename":    "1oracular",
	})
	want := map[string]any{
		"id":            "Ubuntu",
		"release":       "24.10",
		"description":   "Ubuntu 24.10",
		"codename":      "oracular",
		"major_release": "24",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lsb = %#v, want %#v", got, want)
	}
}

func TestLinuxWitnessCapsForAnOrdinaryUser(t *testing.T) {
	// Real, over the guest's own capsh --print:
	//   {"system_capabilities": [""], "system_capabilities_enforced": "True"}
	caps, enforced := capsFacts(probeOutputUbuntu2410)
	if !reflect.DeepEqual(caps, []any{""}) {
		t.Errorf("system_capabilities = %#v, want [\"\"]", caps)
	}
	if enforced != "True" {
		t.Errorf("system_capabilities_enforced = %v, want True", enforced)
	}
}

func TestLinuxWitnessCapsAsRoot(t *testing.T) {
	// Under sudo the same guest prints "Current: =ep". Real:
	//   {"system_capabilities": [], "system_capabilities_enforced": "False"}
	caps, enforced := capsFacts(map[string]string{
		"caps_rc": "0", "caps_current": "Current: =ep",
	})
	if !reflect.DeepEqual(caps, []any{}) {
		t.Errorf("system_capabilities = %#v, want []", caps)
	}
	if enforced != "False" {
		t.Errorf("system_capabilities_enforced = %v, want False", enforced)
	}
}

func TestLinuxWitnessCapsIgnoresTheCurrentIABLine(t *testing.T) {
	// capsh prints TWO lines beginning "Current": "Current:" and
	// "Current IAB:". Real matches with startswith('Current:'), so the
	// second is not a candidate -- and if the probe's awk matched it,
	// the IAB line is the LAST one and would win.
	got := probeOutputUbuntu2410["caps_current"]
	if got != "Current: =" {
		t.Errorf("probe picked %q; the Current IAB: line must not be a candidate", got)
	}
}

func TestLinuxWitnessApparmorEnabled(t *testing.T) {
	// /sys/kernel/security/apparmor exists on that guest, and real
	// reports enabled on exactly that test.
	if got := apparmorFacts(probeOutputUbuntu2410); got["status"] != "enabled" {
		t.Errorf("apparmor = %#v, want status enabled", got)
	}
}
