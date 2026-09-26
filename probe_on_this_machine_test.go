package facts

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The probe is one shell script serving two toolchains — "ip" on
// Linux, "ifconfig" on BSD and macOS — and only one of them can be
// measured on any given machine. The awk programs above are checked
// against CAPTURED macOS output; this runs the whole script on
// whatever machine is running the tests, so the branch that cannot be
// captured here is still exercised somewhere: CI runs ubuntu-latest
// and macos-latest both.
//
// It asserts SHAPE, not values — a CI runner's addresses are its own.
// What it can catch is a branch that produces nothing at all, which is
// exactly how the Linux half would fail if its awk were wrong.
func TestProbeReportsNetworkFactsOnThisMachine(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	cmd := exec.Command(sh, "-c", probeScript)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("running the probe: %v", err)
	}
	got := parseProbe(t, string(out))

	if got["net_interface"] == "" {
		t.Skip("this machine has no default route; nothing to assert")
	}
	for _, key := range []string{"net_cidr", "net_flags", "net_mtu"} {
		if got[key] == "" {
			t.Errorf("%s is empty for default interface %q; the probe's %s branch reported nothing",
				key, got["net_interface"], toolchain())
		}
	}
	// net_cidr must be the two fields defaultIPv4 expects, and its
	// second must be a mask rather than a peer address — the defect
	// that made default_ipv4 vanish on a VPN.
	if _, _, ok := parseIPv4(got["net_cidr"]); !ok {
		t.Errorf("net_cidr = %q, which parseIPv4 refuses: default_ipv4 would be absent on this machine",
			got["net_cidr"])
	}
	// And the whole dict must come out, which is the thing a user sees.
	if d4 := defaultIPv4(got); d4 == nil {
		t.Errorf("default_ipv4 is nil on this machine; probe gave %#v", got)
	} else {
		for _, key := range []string{"address", "netmask", "network", "type", "macaddress", "flags", "device", "mtu"} {
			if _, ok := d4[key]; !ok {
				t.Errorf("default_ipv4 has no %q: %#v", key, d4)
			}
		}
	}
}

func toolchain() string {
	if _, err := exec.LookPath("ip"); err == nil {
		return "ip"
	}
	return "ifconfig"
}

var probeLine = regexp.MustCompile(`^([a-z0-9_]+)='(.*)'$`)

func parseProbe(t *testing.T, out string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if m := probeLine.FindStringSubmatch(line); m != nil {
			got[m[1]] = m[2]
		}
	}
	if len(got) == 0 {
		t.Fatalf("the probe produced nothing parseable:\n%s", out)
	}
	return got
}

// The security collectors' probe halves, on whatever machine is running
// the tests. Like the network test above this asserts SHAPE, because a
// CI runner's capabilities are its own — but CI runs ubuntu-latest as
// well as macos-latest, so the lsb and capsh branches that no Mac can
// reach are still exercised somewhere. The failure it is built to catch
// is the one an awk program fails with: producing nothing at all.
func TestProbeReportsSecurityFactsOnThisMachine(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	out, err := exec.Command(sh, "-c", probeScript).Output()
	if err != nil {
		t.Fatalf("running the probe: %v", err)
	}
	got := parseProbe(t, string(out))

	switch got["apparmor_status"] {
	case "enabled", "disabled":
	default:
		t.Errorf("apparmor_status = %q, want enabled or disabled", got["apparmor_status"])
	}

	if !regexp.MustCompile(`^-?\d+$`).MatchString(got["caps_rc"]) {
		t.Errorf("caps_rc = %q, want an exit status", got["caps_rc"])
	}
	// capsh ran and said something: then the Current: line must have
	// been found, or the awk that looks for it is broken.
	if got["caps_rc"] == "0" && got["caps_current"] == "" {
		t.Error("capsh exited 0 but the probe reported no Current: line")
	}

	lsbKeys := []string{"lsb_id", "lsb_release", "lsb_description", "lsb_codename"}
	anySeen := false
	for _, k := range lsbKeys {
		v, ok := got[k]
		if !ok {
			t.Errorf("%s was not reported at all", k)
			continue
		}
		if v == "" || (v[0] != '0' && v[0] != '1') {
			t.Errorf("%s = %q, want a 0/1 seen-flag followed by the value", k, v)
		}
		if strings.HasPrefix(v, "1") {
			anySeen = true
		}
	}
	// On a machine that HAS lsb_release, at least one label must have
	// come through. This is the assertion a silently-empty awk fails,
	// and it can only fire on Linux.
	if _, err := exec.LookPath("lsb_release"); err == nil && !anySeen {
		t.Error("lsb_release is installed but the probe reported no label; the awk found nothing")
	}
}
