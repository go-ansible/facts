package facts

import (
	"context"
	"io"
	"runtime"
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
	if _, ok := dt["epoch"].(int64); !ok {
		t.Errorf("date_time.epoch = %#v, want int64", dt["epoch"])
	}
	if _, ok := f["processor_vcpus"].(int); !ok {
		t.Errorf("processor_vcpus = %#v, want int", f["processor_vcpus"])
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
