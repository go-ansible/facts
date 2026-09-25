package facts

import (
	"net"
	"strings"
)

// bsdInterfaces parses `ifconfig -a` into one fact dict per interface,
// as real Ansible does on macOS and the BSDs — ansible_facts['en0'],
// ansible_facts['lo0'] and so on, which a playbook reads as
// ansible_facts.en0.ipv4[0].address.
//
// The rules are real's own, from GenericBsdIfconfigNetwork and its
// Darwin subclass (ansible/module_utils/facts/network/), checked
// against the 22 interfaces of a real macOS host: every key, every
// presence rule, every type.
//
// It is deliberately NOT used on Linux. Real parses a Linux host with
// a different collector entirely, reading /sys and /proc rather than
// ifconfig, and what it reports there is not something this parser
// could be said to reproduce without a Linux host to measure against.
// The probe emits its input only when there is no "ip" command.
func bsdInterfaces(out string) map[string]map[string]any {
	ifaces := map[string]map[string]any{}
	var cur map[string]any

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimPrefix(line, "IFC ")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			cur = parseInterfaceLine(strings.Fields(line))
			if cur != nil {
				ifaces[cur["device"].(string)] = cur
			}
			continue
		}
		if cur == nil {
			continue
		}
		words := strings.Fields(line)
		if len(words) == 0 {
			continue
		}
		switch {
		case words[0] == "ether" && len(words) > 1:
			cur["macaddress"] = words[1]
			cur["type"] = "ether"
		case words[0] == "inet" && len(words) > 1:
			cur["ipv4"] = append(cur["ipv4"].([]map[string]any), parseInetLine(words))
		case words[0] == "inet6" && len(words) > 1:
			cur["ipv6"] = append(cur["ipv6"].([]map[string]any), parseInet6Line(words))
		case words[0] == "nd6" && len(words) > 1:
			// nd6 comes AFTER any plain options= line, and real lets
			// it win by simply assigning over it.
			if opts := angleList(words[1]); opts != nil {
				cur["options"] = opts
			}
		case strings.HasPrefix(words[0], "options="):
			if opts := angleList(words[0]); opts != nil {
				cur["options"] = opts
			}
		case words[0] == "media:":
			parseMediaLine(words, cur)
		case words[0] == "status:" && len(words) > 1:
			cur["status"] = words[1]
		}
		// Every other line — a bridge's Configuration block, member:,
		// ifmaxaddr — real ignores, and so does this.
	}
	return ifaces
}

func parseInterfaceLine(words []string) map[string]any {
	if len(words) < 2 || !strings.HasSuffix(words[0], ":") {
		return nil
	}
	flags := angleList(words[1])
	if flags == nil {
		flags = []string{}
	}
	cur := map[string]any{
		"device": strings.TrimSuffix(words[0], ":"),
		"ipv4":   []map[string]any{},
		"ipv6":   []map[string]any{},
		"flags":  flags,
		// Overwritten by an ether line if there is one.
		"macaddress": "unknown",
		"type":       "unknown",
	}
	if hasFlag(flags, "LOOPBACK") {
		cur["type"] = "loopback"
	}
	// Real reads the mtu POSITIONALLY here (words[3]), with a longer
	// form for newer FreeBSD. Every interface line on the measured
	// host has exactly four words, so both agree; taking the token
	// after "mtu" instead would differ only where real is already
	// reading something else.
	for i, w := range words {
		if w == "mtu" && i+1 < len(words) {
			cur["mtu"] = words[i+1]
		}
	}
	return cur
}

// parseInetLine mirrors real's parse_inet_line: the netmask is found
// by its KEYWORD (hex or dotted), the network is address & netmask,
// and the broadcast is the declared one or address | ~netmask.
func parseInetLine(words []string) map[string]any {
	addr := map[string]any{"address": words[1]}
	mask := fieldAfter(words, "netmask")
	ip, m, ok := parseIPv4(words[1] + " " + mask)
	if !ok {
		return addr
	}
	addr["netmask"] = net.IP(m).String()
	addr["network"] = ip.Mask(m).String()
	if b := fieldAfter(words, "broadcast"); b != "" {
		addr["broadcast"] = b
	} else {
		bc := make(net.IP, len(ip))
		for i := range ip {
			bc[i] = ip[i] | ^m[i]
		}
		addr["broadcast"] = bc.String()
	}
	return addr
}

// parseInet6Line is POSITIONAL, exactly as real is, and that is not a
// shortcut — it is the behaviour. Real reads prefix from words[3] only
// when words[2] is "prefixlen", and scope from words[5] only when
// words[4] is "scopeid". macOS writes "secured" between them on a
// secured address:
//
//	inet6 fe80::…%en0 prefixlen 64 secured scopeid 0xe   -> NO scope
//	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1           -> scope 0x1
//
// so real reports no scope for the first. Searching for the keyword
// instead would report 0xe, which is arguably more useful and is not
// what a playbook reading these facts sees.
func parseInet6Line(words []string) map[string]any {
	addr := map[string]any{"address": words[1]}
	if len(words) >= 4 && words[2] == "prefixlen" {
		addr["prefix"] = words[3]
	}
	if len(words) >= 6 && words[4] == "scopeid" {
		addr["scope"] = words[5]
	}
	return addr
}

// parseMediaLine is Darwin's, not the generic BSD one: macOS reports
// no media type real can use, so "media" is the literal "Unknown" and
// the interesting value goes to media_select. A bridge reports
// "<unknown type>", which splits into two words and means something
// different again.
func parseMediaLine(words []string, cur map[string]any) {
	if len(words) < 2 {
		return
	}
	cur["media"] = "Unknown"
	cur["media_select"] = words[1]
	if len(words) > 2 {
		if words[1] == "<unknown" && words[2] == "type>" {
			cur["media_select"] = "Unknown"
			cur["media_type"] = "unknown type"
		} else {
			// Real drops the FIRST and LAST character, whatever
			// they are (words[2][1:-1]), not a particular pair of
			// brackets: macOS writes "(none)" on one interface and
			// "<full-duplex>" on another, and both come out bare.
			// Trimming only parentheses left "<full-duplex>" with
			// its angle brackets on three interfaces.
			cur["media_type"] = trimEnds(words[2])
		}
	}
}

// angleList returns the comma-separated contents of the <...> in a
// token like "flags=8863<UP,BROADCAST>" or "options=201<PERFORMNUD>".
func angleList(token string) []string {
	open := strings.Index(token, "<")
	close := strings.LastIndex(token, ">")
	if open < 0 || close < open {
		return nil
	}
	return splitFlags(token[open+1 : close])
}

// fieldAfter returns the word following the given keyword, or "".
func fieldAfter(words []string, keyword string) string {
	for i, w := range words {
		if w == keyword && i+1 < len(words) {
			return words[i+1]
		}
	}
	return ""
}

// trimEnds drops one character from each end, as real's slice does.
func trimEnds(s string) string {
	if len(s) < 2 {
		return ""
	}
	return s[1 : len(s)-1]
}

// defaultFromInterface builds default_ipv4 or default_ipv6 the way
// real does (merge_default_interface in generic_bsd.py): start from
// the route's own interface and gateway, copy EVERY key of that
// interface's fact dict except its address lists, then merge in the
// first address of the family asked for.
//
// This port used to assemble the dict from separate probe values
// instead, and got away with it only because the default route
// happened to run through a VPN tunnel -- an interface with no media,
// no status and no nd6 options, so the four keys the hand-built
// version could not produce were the four real did not report either.
// The moment the route moved back to a physical interface, real
// reported media, media_select, options and status and this port did
// not.
func defaultFromInterface(ifaces map[string]map[string]any, iface, gateway, family string) map[string]any {
	if iface == "" {
		return nil
	}
	info, ok := ifaces[iface]
	if !ok {
		return nil
	}
	out := map[string]any{"interface": iface}
	if gateway != "" {
		out["gateway"] = gateway
	}
	for k, v := range info {
		if k == "ipv4" || k == "ipv6" {
			continue
		}
		out[k] = v
	}
	// The FIRST address of that family, whatever it is: real picks by
	// matching a route-supplied address only on the BSDs that report
	// one, and falls back to the first everywhere else.
	if addrs, ok := info[family].([]map[string]any); ok && len(addrs) > 0 {
		for k, v := range addrs[0] {
			out[k] = v
		}
	}
	return out
}
