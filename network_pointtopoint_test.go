package facts

import (
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The ifconfig output of a VPN's point-to-point interface, verbatim
// from a macOS host whose default route went through it. The "--> peer"
// between the address and the netmask is the whole problem: it shifts
// every following field by two, so reading the netmask as $4 read the
// PEER ADDRESS instead, parseIPv4 refused it, and default_ipv4
// disappeared entirely.
const utunIfconfig = `utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
	inet 10.215.8.136 --> 10.215.8.136 netmask 0xffffffff
`

// An ordinary NIC, for the other direction.
const en0Ifconfig = `en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether c2:d8:98:70:02:54
	inet6 fe80::1422:23b9:90bb:bf8c%en0 prefixlen 64 secured scopeid 0xe 
	inet 192.168.20.21 netmask 0xffffff00 broadcast 192.168.20.255
	nd6 options=201<PERFORMNUD,DAD>
`

// probeAwk pulls the net_cidr awk program out of the probe script
// itself rather than restating it, so this test exercises THE program
// and cannot drift from it.
func probeAwk(t *testing.T) string {
	t.Helper()
	re := regexp.MustCompile(`p net_cidr "\$\(ifconfig "\$ifc" 2>/dev/null \| awk '([^']*)'\)"`)
	m := re.FindStringSubmatch(probeScript)
	if m == nil {
		t.Fatal("could not find the net_cidr awk program in probeScript; if it was rewritten, update this extractor rather than copying the program")
	}
	return m[1]
}

func TestProbeReadsNetmaskByKeywordNotPosition(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk not available")
	}
	prog := probeAwk(t)

	for _, tc := range []struct {
		name, input, want string
	}{
		{"point-to-point interface", utunIfconfig, "10.215.8.136 0xffffffff"},
		{"ordinary interface", en0Ifconfig, "192.168.20.21 0xffffff00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("awk", prog)
			cmd.Stdin = strings.NewReader(tc.input)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("awk: %v", err)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Measured against ansible-core 2.21.4 on the same host, same moment:
//
//	address=10.215.8.136 interface=utun4 gateway=10.215.8.136
//	netmask=255.255.255.255 network=10.215.8.136 mac=unknown
//	mtu=1400 type=unknown
//
// Note "unknown" for both mac and type, and the dict PRESENT -- this
// port produced no default_ipv4 at all.
func TestDefaultIPv4OnAPointToPointInterface(t *testing.T) {
	got := defaultIPv4(map[string]string{
		"net_cidr":       "10.215.8.136 0xffffffff",
		"net_interface":  "utun4",
		"net_gateway":    "10.215.8.136",
		"net_macaddress": "",
		"net_mtu":        "1400",
	})
	if got == nil {
		t.Fatal("defaultIPv4 = nil: a point-to-point default route must still produce the dict")
	}
	want := map[string]any{
		"address":    "10.215.8.136",
		"netmask":    "255.255.255.255",
		"network":    "10.215.8.136",
		"interface":  "utun4",
		"gateway":    "10.215.8.136",
		"macaddress": "unknown",
		"type":       "unknown",
		"mtu":        "1400",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("default_ipv4[%q] = %#v, want %#v", k, got[k], w)
		}
	}
}

// The other direction: an interface WITH a hardware address keeps
// reporting it, and type "ether" -- which every green run of the
// differential corpus has been asserting against real all along.
func TestDefaultIPv4OnAnEthernetInterface(t *testing.T) {
	got := defaultIPv4(map[string]string{
		"net_cidr":       "192.168.20.21 0xffffff00",
		"net_interface":  "en0",
		"net_gateway":    "192.168.20.254",
		"net_macaddress": "c2:d8:98:70:02:54",
		"net_mtu":        "1500",
	})
	if got["type"] != "ether" {
		t.Errorf("type = %#v, want \"ether\"", got["type"])
	}
	if got["macaddress"] != "c2:d8:98:70:02:54" {
		t.Errorf("macaddress = %#v", got["macaddress"])
	}
	if got["netmask"] != "255.255.255.0" {
		t.Errorf("netmask = %#v, want 255.255.255.0", got["netmask"])
	}
}

// Measured with `| type_debug` against ansible-core 2.21.4, which is
// the only way this class of difference shows: real reports
// default_ipv4.mtu as str where this port reported int, and BOTH
// render "1400" in any message, so every value comparison agreed. The
// difference is real -- `when: ansible_default_ipv4.mtu > 1400`
// errors in real and silently succeeded here.
//
// The same probe found three keys real carries that this port did not:
// broadcast, device and flags.
func TestDefaultIPv4CarriesRealsFullShape(t *testing.T) {
	got := defaultIPv4(map[string]string{
		"net_cidr":       "10.215.8.136 0xffffffff",
		"net_interface":  "utun4",
		"net_gateway":    "10.215.8.136",
		"net_macaddress": "",
		"net_mtu":        "1400",
		"net_flags":      "UP,POINTOPOINT,RUNNING,MULTICAST",
		// Declared by nothing: the value below is COMPUTED.
		"net_broadcast": "",
	})
	// Captured from real on the same host at the same moment.
	want := map[string]any{
		"address":    "10.215.8.136",
		"broadcast":  "10.215.8.136",
		"device":     "utun4",
		"flags":      []string{"UP", "POINTOPOINT", "RUNNING", "MULTICAST"},
		"gateway":    "10.215.8.136",
		"interface":  "utun4",
		"macaddress": "unknown",
		"mtu":        "1400",
		"netmask":    "255.255.255.255",
		"network":    "10.215.8.136",
		"type":       "unknown",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default_ipv4 =\n  %#v\nwant\n  %#v", got, want)
	}
}

// With no hardware address, LOOPBACK in the flags makes the type
// "loopback" rather than "unknown" -- real's rule, witnessed on lo0's
// own fact dict.
func TestDefaultIPv4TypeFromLoopbackFlag(t *testing.T) {
	got := defaultIPv4(map[string]string{
		"net_cidr":      "127.0.0.1 0xff000000",
		"net_interface": "lo0",
		"net_flags":     "UP,LOOPBACK,RUNNING,MULTICAST",
	})
	if got["type"] != "loopback" {
		t.Errorf("type = %#v, want \"loopback\"", got["type"])
	}
	if got["macaddress"] != "unknown" {
		t.Errorf("macaddress = %#v, want \"unknown\"", got["macaddress"])
	}
}

// The probe reports only the broadcast an interface DECLARES. A
// point-to-point interface declares none -- its "--> peer" field is
// not a broadcast address, and real never reads it as one -- so the
// probe yields nothing there and defaultIPv4 computes the value.
func TestProbeReadsOnlyADeclaredBroadcast(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk not available")
	}
	re := regexp.MustCompile(`p net_broadcast "\$\(ifconfig "\$ifc" 2>/dev/null \| awk '([^']*)'\)"`)
	m := re.FindStringSubmatch(probeScript)
	if m == nil {
		t.Fatal("could not find the net_broadcast awk program in probeScript")
	}
	for _, tc := range []struct{ name, input, want string }{
		{"point-to-point declares none", utunIfconfig, ""},
		{"broadcast keyword", en0Ifconfig, "192.168.20.255"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("awk", m[1])
			cmd.Stdin = strings.NewReader(tc.input)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("awk: %v", err)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The flags program, against the same two captures.
func TestProbeReadsFlagsFromTheInterfaceLine(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk not available")
	}
	re := regexp.MustCompile(`p net_flags "\$\(ifconfig "\$ifc" 2>/dev/null \| awk '([^']*)'\)"`)
	m := re.FindStringSubmatch(probeScript)
	if m == nil {
		t.Fatal("could not find the net_flags awk program in probeScript")
	}
	for _, tc := range []struct{ name, input, want string }{
		{"point-to-point", utunIfconfig, "UP,POINTOPOINT,RUNNING,MULTICAST"},
		// en0's SECOND line carries options=6460<TSO4,...>; taking the
		// first match rather than the first LINE would read that.
		{"ordinary", en0Ifconfig, "UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("awk", m[1])
			cmd.Stdin = strings.NewReader(tc.input)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("awk: %v", err)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The rule that reading the peer got right by luck. On the only
// point-to-point interface available to measure -- a /32 -- the peer
// and the computed broadcast are the same address, so both rules
// agreed. On an ordinary tunnel they do not agree at all, and it is
// the computed one real reports.
func TestBroadcastIsComputedNotThePeer(t *testing.T) {
	got := defaultIPv4(map[string]string{
		"net_cidr":      "10.8.0.2 0xffffff00",
		"net_interface": "utun9",
		"net_flags":     "UP,POINTOPOINT,RUNNING,MULTICAST",
		"net_broadcast": "", // a point-to-point interface declares none
	})
	if got["broadcast"] != "10.8.0.255" {
		t.Errorf("broadcast = %#v, want \"10.8.0.255\" (address|~netmask); the peer would be 10.8.0.1", got["broadcast"])
	}
	if got["network"] != "10.8.0.0" {
		t.Errorf("network = %#v, want \"10.8.0.0\"", got["network"])
	}
}

// A declared broadcast is used as declared, never recomputed.
func TestDeclaredBroadcastWins(t *testing.T) {
	got := defaultIPv4(map[string]string{
		"net_cidr":       "192.168.20.21 0xffffff00",
		"net_interface":  "en0",
		"net_macaddress": "c2:d8:98:70:02:54",
		"net_broadcast":  "192.168.20.255",
	})
	if got["broadcast"] != "192.168.20.255" {
		t.Errorf("broadcast = %#v", got["broadcast"])
	}
}
