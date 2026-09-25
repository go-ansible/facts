// Package facts implements Ansible's `setup` module / gather_facts:
// probing a target for a portable subset of system facts (Ansible's own
// ansible_facts namespace) using only POSIX shell commands present on
// virtually every real target, no Python required.
package facts

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	remoteexec "github.com/go-remoteexec/transport"
)

// probeScript prints one "key=value" line per fact (values shell-quoted
// with surrounding single quotes so embedded spaces survive), so a
// single round trip gathers everything.
const probeScript = `
p() { printf "%s='%s'\n" "$1" "$2"; }
p system "$(uname -s)"
p kernel "$(uname -r)"
p architecture "$(uname -m)"
p hostname "$(hostname -s 2>/dev/null || hostname)"
p fqdn "$(hostname -f 2>/dev/null || hostname)"
p date_time_epoch "$(date -u +%s 2>/dev/null)"
if [ -f /etc/os-release ]; then
  distro_id=$(. /etc/os-release && echo "$ID")
  distro_version=$(. /etc/os-release && echo "$VERSION_ID")
  distro_like=$(. /etc/os-release && echo "$ID_LIKE")
  p distribution "$distro_id"
  p distribution_version "$distro_version"
  p distribution_id_like "$distro_like"
elif [ "$(uname -s)" = "Darwin" ]; then
  p distribution "MacOSX"
  p distribution_version "$(sw_vers -productVersion 2>/dev/null)"
fi
p nproc "$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null)"
p user_id "$(id -un 2>/dev/null)"
p effective_user_id "$(id -u 2>/dev/null)"
p effective_group_id "$(id -g 2>/dev/null)"
p real_user_id "$(id -ru 2>/dev/null || id -u 2>/dev/null)"
p real_group_id "$(id -rg 2>/dev/null || id -g 2>/dev/null)"
p distribution_release "$(if [ -f /etc/os-release ]; then . /etc/os-release && echo "$VERSION_CODENAME"; else uname -r; fi)"
p memtotal_kb "$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || (sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024)}'))"
p pkg_mgr "$(command -v apt-get >/dev/null 2>&1 && echo apt || (command -v dnf >/dev/null 2>&1 && echo dnf) || (command -v yum >/dev/null 2>&1 && echo yum) || (command -v brew >/dev/null 2>&1 && echo brew) || echo unknown)"
p nodename "$(uname -n)"
p machine "$(uname -m)"
p kernel_version "$(uname -v)"
p user_dir "$HOME"
p user_shell "$SHELL"
p user_uid "$(id -u 2>/dev/null)"
p user_gid "$(id -g 2>/dev/null)"
p processor_cores "$(sysctl -n hw.physicalcpu 2>/dev/null || lscpu -p=Core 2>/dev/null | grep -vc '^#' || echo)"
p uptime_seconds "$(if [ -r /proc/uptime ]; then cut -d. -f1 /proc/uptime; else boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p'); [ -n "$boot" ] && echo $(( $(date +%s) - boot )); fi)"
p memfree_mb "$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo 2>/dev/null || (pages=$(vm_stat 2>/dev/null | awk '/Pages free/{gsub(/\./,"",$3); print $3}'); [ -n "$pages" ] && echo $(( pages * 4096 / 1048576 )) ))"
p service_mgr "$(if [ -d /run/systemd/system ]; then echo systemd; elif command -v launchctl >/dev/null 2>&1; then echo launchd; elif [ -f /sbin/init ]; then echo sysvinit; else echo unknown; fi)"
# --- network ---------------------------------------------------------
# The DEFAULT route's interface and that interface's address. Both
# toolchains are handled because neither exists on the other: "ip" on
# Linux, "route"/"ifconfig" on BSD and macOS.
if command -v ip >/dev/null 2>&1; then
  def_line=$(ip -4 route show default 2>/dev/null | head -1)
  ifc=$(echo "$def_line" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
  p net_interface "$ifc"
  p net_gateway "$(echo "$def_line" | sed -n 's/.*default via \([^ ]*\).*/\1/p')"
  if [ -n "$ifc" ]; then
    p net_cidr "$(ip -4 -o addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | head -1)"
    p net_macaddress "$(cat /sys/class/net/"$ifc"/address 2>/dev/null)"
    p net_mtu "$(cat /sys/class/net/"$ifc"/mtu 2>/dev/null)"
  fi
  p net_all_ipv4 "$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | tr '\n' ' ')"
  p net_interfaces "$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ' ')"
elif command -v ifconfig >/dev/null 2>&1; then
  ifc=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
  p net_interface "$ifc"
  p net_gateway "$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')"
  if [ -n "$ifc" ]; then
    p net_cidr "$(ifconfig "$ifc" 2>/dev/null | awk '/inet /{a="";m="";for(i=1;i<=NF;i++){if($i=="inet")a=$(i+1);else if($i=="netmask")m=$(i+1)};if(a!=""){print a" "m;exit}}')"
    p net_macaddress "$(ifconfig "$ifc" 2>/dev/null | awk '/ether /{print $2; exit}')"
    p net_mtu "$(ifconfig "$ifc" 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p' | head -1)"
  fi
  p net_all_ipv4 "$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | tr '\n' ' ')"
  p net_interfaces "$(ifconfig -l 2>/dev/null)"
fi
# LAST, and every line prefixed: a value spanning lines cannot then
# be read back as one of the facts above. parseKV stops here.
env | sed 's/^/ENV /'
`

// Gather probes conn for a portable subset of Ansible's ansible_facts:
// system/kernel/architecture (uname), hostname/fqdn, distribution/
// distribution_version/os_family (parsed /etc/os-release on Linux,
// sw_vers on macOS), date_time.epoch, processor_count, user_id, and
// pkg_mgr (the package manager available, for module dispatch).
//
// The returned map's keys are bare (e.g. "system", not
// "ansible_system") — see vars.InjectFacts for the ansible_facts /
// ansible_<name> namespacing a caller applies on top.
func Gather(ctx context.Context, conn remoteexec.Connection) (map[string]any, error) {
	res, err := conn.Exec(ctx, probeScript, nil)
	if err != nil {
		return nil, fmt.Errorf("facts: gathering: %w", err)
	}
	if res.RC != 0 {
		return nil, fmt.Errorf("facts: gathering: exit %d: %s", res.RC, strings.TrimSpace(res.Stderr))
	}

	// Everything before the first ENV line. An environment variable
	// whose value spans lines would otherwise have its continuation
	// read as a fact — a host could name a fact by exporting one.
	facts, _, _ := strings.Cut(res.Stdout, "\nENV ")
	raw := parseKV(facts)

	out := map[string]any{
		// Real sets both on every gathered host; a playbook reads
		// gather_subset to know what it asked for.
		"_ansible_facts_gathered": true,
		"gather_subset":           []any{"all"},
		"env":                     parseEnv(res.Stdout),
		"system":                  raw["system"],
		"kernel":                  raw["kernel"],
		"architecture":            raw["architecture"],
		"hostname":                raw["hostname"],
		"fqdn":                    raw["fqdn"],
		"user_id":                 raw["user_id"],
		"pkg_mgr":                 raw["pkg_mgr"],
		"os_family":               osFamily(raw["distribution"], raw["distribution_id_like"], raw["system"]),
	}
	if raw["distribution"] != "" {
		out["distribution"] = raw["distribution"]
	}
	if raw["distribution_version"] != "" {
		out["distribution_version"] = raw["distribution_version"]
		// The part before the first dot — what a `when:` compares
		// against to branch on a major release.
		major, _, _ := strings.Cut(raw["distribution_version"], ".")
		out["distribution_major_version"] = major
	}
	if raw["distribution_release"] != "" {
		out["distribution_release"] = raw["distribution_release"]
	}
	// Measured, and worth stating because two of these read backwards:
	// real reports the ID fields as INTEGERS and the processor counts
	// and date_time.epoch as STRINGS. This port had effective_user_id
	// a string and processor_vcpus and epoch integers, so a comparison
	// against any of them behaved differently from real's.
	for _, k := range []string{
		"effective_user_id", "effective_group_id",
		"user_uid", "user_gid", "real_user_id", "real_group_id",
		"memfree_mb", "uptime_seconds",
	} {
		if n, err := strconv.Atoi(raw[k]); err == nil {
			out[k] = n
		}
	}
	for _, k := range []string{
		"nodename", "machine", "kernel_version", "user_dir", "user_shell",
		"service_mgr", "processor_cores",
	} {
		if raw[k] != "" {
			out[k] = raw[k]
		}
	}
	// The fqdn minus the hostname, empty when the host has no domain —
	// real reports an empty string there rather than omitting it.
	out["domain"] = strings.TrimPrefix(strings.TrimPrefix(raw["fqdn"], raw["hostname"]), ".")
	if kb, err := strconv.Atoi(raw["memtotal_kb"]); err == nil && kb > 0 {
		out["memtotal_mb"] = kb / 1024
	}
	if list := splitFields(raw["net_all_ipv4"]); len(list) > 0 {
		out["all_ipv4_addresses"] = list
	}
	if list := splitFields(raw["net_interfaces"]); len(list) > 0 {
		out["interfaces"] = list
	}
	if d4 := defaultIPv4(raw); len(d4) > 0 {
		out["default_ipv4"] = d4
	}
	if raw["nproc"] != "" {
		out["processor_vcpus"] = raw["nproc"]
	}
	if raw["date_time_epoch"] != "" {
		out["date_time"] = map[string]any{"epoch": raw["date_time_epoch"]}
	}
	return out, nil
}

// osFamily maps a distribution id (and, when set, its ID_LIKE family)
// to Ansible's conventional os_family value.
func osFamily(distribution, idLike, system string) string {
	d := strings.ToLower(distribution)
	like := strings.ToLower(idLike)
	switch {
	case d == "macosx" || system == "Darwin":
		return "Darwin"
	case d == "ubuntu" || d == "debian" || strings.Contains(like, "debian"):
		return "Debian"
	case d == "rhel" || d == "centos" || d == "fedora" || d == "rocky" || d == "almalinux" ||
		strings.Contains(like, "rhel") || strings.Contains(like, "fedora"):
		return "RedHat"
	case d == "alpine":
		return "Alpine"
	case d == "arch" || strings.Contains(like, "arch"):
		return "Archlinux"
	case strings.HasPrefix(d, "opensuse") || d == "sles" || strings.Contains(like, "suse"):
		return "Suse"
	default:
		return distribution
	}
}

// parseKV parses lines of the form key='value' (produced by
// probeScript's p() helper) into a map. A key that never appeared maps
// to "" when looked up, not a missing entry — every caller here already
// tolerates an empty string.
func parseKV(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.TrimSuffix(strings.TrimPrefix(val, "'"), "'")
		out[key] = val
	}
	return out
}

// parseEnv reads the ENV-prefixed lines the probe emits, one
// environment variable each, splitting on the FIRST "=" so a value
// containing one survives.
//
// A value spanning several lines is skipped rather than truncated: its
// continuation is indistinguishable from the next variable, and half a
// value is worse than none.
func parseEnv(stdout string) map[string]any {
	out := map[string]any{}
	for _, line := range strings.Split(stdout, "\n") {
		rest, ok := strings.CutPrefix(line, "ENV ")
		if !ok {
			continue
		}
		name, value, found := strings.Cut(rest, "=")
		if !found || name == "" {
			continue
		}
		out[name] = value
	}
	return out
}

// splitFields turns a space-separated probe value into a list, which
// is the shape real reports these in.
func splitFields(s string) []any {
	out := []any{}
	for _, f := range strings.Fields(s) {
		out = append(out, f)
	}
	return out
}

// defaultIPv4 assembles real's ansible_facts.default_ipv4 — the
// address of the interface the DEFAULT ROUTE leaves by, which is what
// a template means by "this host's IP".
//
// Only the keys both platforms can answer are reported. Real adds
// several BSD-only ones on macOS (media, media_select, options,
// status, flags) and a different set on Linux; inventing a common
// value for those would be guessing, so they are absent rather than
// wrong.
func defaultIPv4(raw map[string]string) map[string]any {
	addr, mask, ok := parseIPv4(raw["net_cidr"])
	if !ok {
		return nil
	}
	// An interface with no hardware address is not an ethernet one,
	// and real says so rather than leaving the keys out: a VPN's
	// point-to-point interface reports macaddress "unknown" and type
	// "unknown", where an ordinary NIC reports its MAC and "ether".
	// Both directions are measured -- the ethernet one against every
	// run of the differential corpus, the other against a run made
	// while the default route went through a utun interface.
	macaddress, ifaceType := raw["net_macaddress"], "ether"
	if macaddress == "" {
		macaddress, ifaceType = "unknown", "unknown"
	}
	out := map[string]any{
		"address":    addr.String(),
		"netmask":    net.IP(mask).String(),
		"network":    addr.Mask(mask).String(),
		"type":       ifaceType,
		"macaddress": macaddress,
	}
	for key, value := range map[string]string{
		"interface": raw["net_interface"],
		"gateway":   raw["net_gateway"],
	} {
		if value != "" {
			out[key] = value
		}
	}
	if mtu, err := strconv.Atoi(raw["net_mtu"]); err == nil {
		out["mtu"] = mtu
	}
	return out
}

// parseIPv4 reads the two shapes the probe can produce, because the
// two toolchains disagree: "192.168.1.152/24" from Linux's ip, and
// "192.168.1.152 0xffffff00" from macOS's ifconfig, whose mask is
// HEXADECIMAL and not an address at all.
func parseIPv4(value string) (net.IP, net.IPMask, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil, false
	}
	if addr, cidr, err := net.ParseCIDR(value); err == nil {
		return addr.To4(), cidr.Mask, addr.To4() != nil
	}
	addrText, maskText, found := strings.Cut(value, " ")
	if !found {
		return nil, nil, false
	}
	addr := net.ParseIP(strings.TrimSpace(addrText)).To4()
	if addr == nil {
		return nil, nil, false
	}
	bits, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(maskText), "0x"), 16, 32)
	if err != nil {
		return nil, nil, false
	}
	mask := net.IPv4Mask(byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
	return addr, mask, true
}
