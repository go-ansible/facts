package facts

import (
	"os/exec"
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
		"mtu":        1400,
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
