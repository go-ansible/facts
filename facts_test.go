package facts

import (
	"context"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"

	remoteexec "github.com/go-remoteexec/transport"
)

func TestGatherLocal(t *testing.T) {
	f, err := Gather(context.Background(), remoteexec.NewLocal())
	if err != nil {
		t.Fatal(err)
	}

	wantSystem := map[string]string{"darwin": "Darwin", "linux": "Linux"}[runtime.GOOS]
	if wantSystem == "" {
		t.Skipf("no expected uname -s mapping for GOOS=%s", runtime.GOOS)
	}
	if f["system"] != wantSystem {
		t.Errorf("system = %v, want %v", f["system"], wantSystem)
	}
	if f["hostname"] == "" {
		t.Error("hostname is empty")
	}
	if f["architecture"] == "" {
		t.Error("architecture is empty")
	}
	if f["os_family"] == "" {
		t.Error("os_family is empty")
	}
	if runtime.GOOS == "darwin" {
		if f["os_family"] != "Darwin" {
			t.Errorf("os_family = %v, want Darwin", f["os_family"])
		}
		if f["distribution"] != "MacOSX" {
			t.Errorf("distribution = %v, want MacOSX", f["distribution"])
		}
	}
	dt, ok := f["date_time"].(map[string]any)
	if !ok {
		t.Fatalf("date_time = %#v, want a map", f["date_time"])
	}
	// STRINGS, both of them — this asserted int64 and int, which was
	// this port's own shape rather than the reference's. Measured
	// against real ansible-core 2.21.4, where date_time.epoch and
	// processor_vcpus come back as str and the ID fields as int; two
	// of the three read backwards from what one would guess.
	if _, ok := dt["epoch"].(string); !ok {
		t.Errorf("date_time.epoch = %#v, want a string", dt["epoch"])
	}
	if _, ok := f["processor_vcpus"].(string); !ok {
		t.Errorf("processor_vcpus = %#v, want a string", f["processor_vcpus"])
	}
	for _, k := range []string{"effective_user_id", "effective_group_id", "user_uid", "user_gid"} {
		if _, ok := f[k].(int); !ok {
			t.Errorf("%s = %#v, want an int", k, f[k])
		}
	}
}

func TestGatherTransportError(t *testing.T) {
	if _, err := Gather(context.Background(), errConn{}); err == nil {
		t.Fatal("want error")
	}
}

func TestGatherNonZeroExit(t *testing.T) {
	conn := scriptedConn{rc: 1, stderr: "nope"}
	if _, err := Gather(context.Background(), conn); err == nil {
		t.Fatal("want error for non-zero exit")
	}
}

func TestOsFamily(t *testing.T) {
	cases := []struct {
		distro, like, system, want string
	}{
		{"ubuntu", "", "Linux", "Debian"},
		{"debian", "", "Linux", "Debian"},
		{"linuxmint", "ubuntu debian", "Linux", "Debian"},
		{"rhel", "", "Linux", "RedHat"},
		{"centos", "", "Linux", "RedHat"},
		{"fedora", "", "Linux", "RedHat"},
		{"rocky", "", "Linux", "RedHat"},
		{"almalinux", "", "Linux", "RedHat"},
		{"amzn", "fedora", "Linux", "RedHat"},
		{"alpine", "", "Linux", "Alpine"},
		{"arch", "", "Linux", "Archlinux"},
		{"manjaro", "arch", "Linux", "Archlinux"},
		{"opensuse-leap", "", "Linux", "Suse"},
		{"sles", "", "Linux", "Suse"},
		{"MacOSX", "", "Darwin", "Darwin"},
		{"", "", "Darwin", "Darwin"},
		{"someunknowndistro", "", "Linux", "someunknowndistro"},
	}
	for _, c := range cases {
		if got := osFamily(c.distro, c.like, c.system); got != c.want {
			t.Errorf("osFamily(%q,%q,%q) = %q, want %q", c.distro, c.like, c.system, got, c.want)
		}
	}
}

func TestParseKV(t *testing.T) {
	got := parseKV("system='Linux'\narchitecture='x86_64'\n\nmalformed-line\n")
	if got["system"] != "Linux" || got["architecture"] != "x86_64" {
		t.Fatalf("parseKV = %v", got)
	}
	if _, ok := got["malformed-line"]; ok {
		t.Fatal("a line with no '=' should be ignored")
	}
}

func TestGatherEmptyOptionalFields(t *testing.T) {
	conn := scriptedConn{stdout: "system='Linux'\n"}
	f, err := Gather(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f["distribution"]; ok {
		t.Error("distribution should be absent when the probe reported none")
	}
	if _, ok := f["date_time"]; ok {
		t.Error("date_time should be absent when epoch failed to parse")
	}
	if _, ok := f["processor_vcpus"]; ok {
		t.Error("processor_vcpus should be absent when nproc failed to parse")
	}
}

// errConn and scriptedConn are minimal Connection fakes local to this
// package's tests (facts has no production dependency on modules'
// fakeConn, so it gets its own tiny one).

type errConn struct{ remoteexec.Connection }

func (errConn) Exec(ctx context.Context, cmd string, stdin io.Reader) (remoteexec.Result, error) {
	return remoteexec.Result{}, errTransport
}

type scriptedConn struct {
	remoteexec.Connection
	stdout, stderr string
	rc             int
}

func (c scriptedConn) Exec(ctx context.Context, cmd string, stdin io.Reader) (remoteexec.Result, error) {
	return remoteexec.Result{Stdout: c.stdout, Stderr: c.stderr, RC: c.rc}, nil
}

var errTransport = &transportErr{"boom"}

type transportErr struct{ msg string }

func (e *transportErr) Error() string { return e.msg }

// TestParseEnvAndFactIsolation: the probe emits the environment last,
// every line prefixed, and the fact parser stops before it — so a
// variable whose VALUE spans lines cannot have its continuation read
// back as a fact. A host could otherwise name its own facts just by
// exporting one.
func TestParseEnvAndFactIsolation(t *testing.T) {
	stdout := "system='Darwin'\nhostname='h1'\n" +
		"ENV HOME=/root\n" +
		"ENV PATH=/usr/bin:/bin\n" +
		"ENV EQUALS=a=b\n" +
		"ENV EVIL=first\nsystem='pwned'\n"

	facts, _, _ := strings.Cut(stdout, "\nENV ")
	raw := parseKV(facts)
	if raw["system"] != "Darwin" {
		t.Errorf("system = %q, want it untouched by the environment", raw["system"])
	}

	env := parseEnv(stdout)
	if env["HOME"] != "/root" {
		t.Errorf("HOME = %v", env["HOME"])
	}
	// Split on the FIRST "=", so a value containing one survives.
	if env["EQUALS"] != "a=b" {
		t.Errorf("EQUALS = %v, want %q", env["EQUALS"], "a=b")
	}
	// The continuation of a multi-line value is not a variable.
	if _, ok := env["system'"]; ok {
		t.Error("a continuation line was read as a variable")
	}
}

// TestParseIPv4BothToolchains: the two toolchains disagree about how
// an address and its mask are written, and one of them is not an
// address at all — macOS's ifconfig gives a HEXADECIMAL mask.
func TestParseIPv4BothToolchains(t *testing.T) {
	for _, tc := range []struct {
		in                     string
		addr, netmask, network string
	}{
		// Linux, `ip -4 -o addr show`.
		{"192.168.1.152/24", "192.168.1.152", "255.255.255.0", "192.168.1.0"},
		{"10.0.5.7/8", "10.0.5.7", "255.0.0.0", "10.0.0.0"},
		{"172.16.34.9/12", "172.16.34.9", "255.240.0.0", "172.16.0.0"},
		// macOS, `ifconfig`: address and a hex mask, space separated.
		{"192.168.1.152 0xffffff00", "192.168.1.152", "255.255.255.0", "192.168.1.0"},
		{"10.0.5.7 0xff000000", "10.0.5.7", "255.0.0.0", "10.0.0.0"},
		{"172.16.34.9 0xfff00000", "172.16.34.9", "255.240.0.0", "172.16.0.0"},
	} {
		addr, mask, ok := parseIPv4(tc.in)
		if !ok {
			t.Errorf("parseIPv4(%q) failed", tc.in)
			continue
		}
		if addr.String() != tc.addr {
			t.Errorf("%q: address = %s, want %s", tc.in, addr, tc.addr)
		}
		if got := net.IP(mask).String(); got != tc.netmask {
			t.Errorf("%q: netmask = %s, want %s", tc.in, got, tc.netmask)
		}
		if got := addr.Mask(mask).String(); got != tc.network {
			t.Errorf("%q: network = %s, want %s", tc.in, got, tc.network)
		}
	}
	for _, bad := range []string{"", "not-an-address", "192.168.1.1", "192.168.1.1 zz", "::1/128"} {
		if _, _, ok := parseIPv4(bad); ok {
			t.Errorf("parseIPv4(%q) succeeded, want a refusal", bad)
		}
	}
}

// TestDefaultIPv4OmitsWhatItCannotAnswer: real reports several
// platform-only keys (media, options, status on macOS). Inventing a
// common value for those would be guessing, so they are absent — and
// the keys that ARE reported must all be there.
func TestDefaultIPv4OmitsWhatItCannotAnswer(t *testing.T) {
	d4 := defaultIPv4(map[string]string{
		"net_cidr":       "192.168.1.152 0xffffff00",
		"net_interface":  "en0",
		"net_gateway":    "192.168.1.254",
		"net_macaddress": "6e:8f:60:25:76:16",
		"net_mtu":        "1500",
	})
	want := map[string]any{
		"address": "192.168.1.152", "netmask": "255.255.255.0",
		"network": "192.168.1.0", "type": "ether", "interface": "en0",
		"device": "en0", "gateway": "192.168.1.254",
		// Computed from address and netmask, as real does when the
		// interface declares none.
		"broadcast":  "192.168.1.255",
		"macaddress": "6e:8f:60:25:76:16",
		// A STRING, as real reports it — see the type_debug
		// measurement in network_pointtopoint_test.go.
		"mtu": "1500",
		// Always present, even when the probe parsed none.
		"flags": []string{},
	}
	if !reflect.DeepEqual(d4, want) {
		t.Errorf("default_ipv4 =\n  %#v\nwant\n  %#v", d4, want)
	}
	// No default route, nothing to report.
	if d4 := defaultIPv4(map[string]string{"net_interface": "en0"}); d4 != nil {
		t.Errorf("default_ipv4 = %#v with no address, want nil", d4)
	}
}
