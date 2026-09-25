package facts

import (
	"reflect"
	"testing"
)

// The fixtures below keep the exact SHAPE of a real macOS ifconfig --
// which is what the parser is tested on -- with fabricated addresses.
// The host these rules were measured against has its own MAC
// addresses and local IPs, and those are not something to publish.
// Every expected value was computed by running real Ansible on that
// host and then substituting the same way.
const ifconfigFixture = `IFC lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
IFC 	options=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
IFC 	inet 127.0.0.1 netmask 0xff000000
IFC 	inet6 ::1 prefixlen 128
IFC 	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
IFC 	nd6 options=201<PERFORMNUD,DAD>
IFC gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
IFC en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
IFC 	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
IFC 	ether 02:00:5e:10:00:01
IFC 	inet6 fe80::dead:beef:cafe:0001%en0 prefixlen 64 secured scopeid 0xe
IFC 	inet 198.51.100.21 netmask 0xffffff00 broadcast 198.51.100.255
IFC 	nd6 options=201<PERFORMNUD,DAD>
IFC 	media: autoselect
IFC 	status: active
IFC en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
IFC 	options=460<TSO4,TSO6,CHANNEL_IO>
IFC 	ether 02:00:5e:10:00:02
IFC 	media: autoselect <full-duplex>
IFC 	status: inactive
IFC ap1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
IFC 	options=400<CHANNEL_IO>
IFC 	ether 02:00:5e:10:00:03
IFC 	nd6 options=201<PERFORMNUD,DAD>
IFC 	media: autoselect (none)
IFC bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
IFC 	options=63<RXCSUM,TXCSUM,TSO4,TSO6>
IFC 	ether 02:00:5e:10:00:04
IFC 	Configuration:
IFC 		id 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
IFC 		ipfilter disabled flags 0x0
IFC 	member: en1 flags=3<LEARNING,DISCOVER>
IFC 	nd6 options=201<PERFORMNUD,DAD>
IFC 	media: <unknown type>
IFC 	status: inactive
IFC utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
IFC 	inet 203.0.113.136 --> 203.0.113.136 netmask 0xffffffff
`

func TestBSDInterfaces(t *testing.T) {
	got := bsdInterfaces(ifconfigFixture)

	want := map[string]map[string]any{
		// A loopback: type comes from the FLAG, not a hardware
		// address, and it has two ipv6 entries -- only the second
		// carries a scope.
		"lo0": {
			"device":     "lo0",
			"flags":      []string{"UP", "LOOPBACK", "RUNNING", "MULTICAST"},
			"macaddress": "unknown",
			"mtu":        "16384",
			"options":    []string{"PERFORMNUD", "DAD"},
			"type":       "loopback",
			"ipv4": []map[string]any{{
				"address": "127.0.0.1", "netmask": "255.0.0.0",
				"network": "127.0.0.0", "broadcast": "127.255.255.255",
			}},
			"ipv6": []map[string]any{
				{"address": "::1", "prefix": "128"},
				{"address": "fe80::1%lo0", "prefix": "64", "scope": "0x1"},
			},
		},
		// Nothing but an interface line: no options, no media, no
		// status keys at all -- absent, not empty.
		"gif0": {
			"device": "gif0", "flags": []string{"POINTOPOINT", "MULTICAST"},
			"macaddress": "unknown", "mtu": "1280", "type": "unknown",
			"ipv4": []map[string]any{}, "ipv6": []map[string]any{},
		},
		// An ordinary NIC. The nd6 options WIN over the plain
		// options= line above them, and the secured ipv6 address gets
		// NO scope because "secured" shifts the positional field real
		// reads.
		"en0": {
			"device": "en0",
			"flags":  []string{"UP", "BROADCAST", "SMART", "RUNNING", "SIMPLEX", "MULTICAST"},
			"ipv4": []map[string]any{{
				"address": "198.51.100.21", "netmask": "255.255.255.0",
				"network": "198.51.100.0", "broadcast": "198.51.100.255",
			}},
			"ipv6":       []map[string]any{{"address": "fe80::dead:beef:cafe:0001%en0", "prefix": "64"}},
			"macaddress": "02:00:5e:10:00:01",
			"media":      "Unknown", "media_select": "autoselect",
			"mtu": "1500", "options": []string{"PERFORMNUD", "DAD"},
			"status": "active", "type": "ether",
		},
		// media_type keeps whatever is inside the brackets, with ONE
		// character dropped from each end whatever they are.
		"en1": {
			"device": "en1",
			"flags":  []string{"UP", "BROADCAST", "SMART", "RUNNING", "PROMISC", "SIMPLEX", "MULTICAST"},
			"ipv4":   []map[string]any{}, "ipv6": []map[string]any{},
			"macaddress": "02:00:5e:10:00:02",
			"media":      "Unknown", "media_select": "autoselect", "media_type": "full-duplex",
			"mtu": "1500", "status": "inactive", "type": "ether",
			"options": []string{"TSO4", "TSO6", "CHANNEL_IO"},
		},
		// "(none)" is the other bracket shape, same rule.
		"ap1": {
			"device": "ap1",
			"flags":  []string{"BROADCAST", "SMART", "SIMPLEX", "MULTICAST"},
			"ipv4":   []map[string]any{}, "ipv6": []map[string]any{},
			"macaddress": "02:00:5e:10:00:03",
			"media":      "Unknown", "media_select": "autoselect", "media_type": "none",
			"mtu": "1500", "options": []string{"PERFORMNUD", "DAD"}, "type": "ether",
		},
		// "<unknown type>" splits into two words and means something
		// else again: media_select becomes "Unknown". The bridge's
		// Configuration block and member: line are ignored.
		"bridge0": {
			"device": "bridge0",
			"flags":  []string{"UP", "BROADCAST", "SMART", "RUNNING", "SIMPLEX", "MULTICAST"},
			"ipv4":   []map[string]any{}, "ipv6": []map[string]any{},
			"macaddress": "02:00:5e:10:00:04",
			"media":      "Unknown", "media_select": "Unknown", "media_type": "unknown type",
			"mtu": "1500", "options": []string{"PERFORMNUD", "DAD"},
			"status": "inactive", "type": "ether",
		},
		// Point-to-point: the "--> peer" is NOT the broadcast. With a
		// /32 the computed broadcast happens to equal the address,
		// which is why reading the peer looked right for a while.
		"utun4": {
			"device": "utun4",
			"flags":  []string{"UP", "POINTOPOINT", "RUNNING", "MULTICAST"},
			"ipv4": []map[string]any{{
				"address": "203.0.113.136", "netmask": "255.255.255.255",
				"network": "203.0.113.136", "broadcast": "203.0.113.136",
			}},
			"ipv6": []map[string]any{}, "macaddress": "unknown",
			"mtu": "1400", "type": "unknown",
		},
	}

	if len(got) != len(want) {
		t.Fatalf("parsed %d interfaces (%v), want %d", len(got), keysOf(got), len(want))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s missing", name)
			continue
		}
		if !reflect.DeepEqual(g, w) {
			for _, k := range unionKeys(g, w) {
				if !reflect.DeepEqual(g[k], w[k]) {
					t.Errorf("%s[%q] = %#v, want %#v", name, k, g[k], w[k])
				}
			}
		}
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func unionKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// An empty input is not an error: a Linux host takes the "ip" branch
// and supplies nothing here.
func TestBSDInterfacesWithNoInput(t *testing.T) {
	if got := bsdInterfaces(""); len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}
