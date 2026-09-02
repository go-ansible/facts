// Package facts implements Ansible's `setup` module / gather_facts:
// probing a target for a portable subset of system facts (Ansible's own
// ansible_facts namespace) using only POSIX shell commands present on
// virtually every real target, no Python required.
package facts

import (
	"context"
	"fmt"
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
p pkg_mgr "$(command -v apt-get >/dev/null 2>&1 && echo apt || (command -v dnf >/dev/null 2>&1 && echo dnf) || (command -v yum >/dev/null 2>&1 && echo yum) || (command -v brew >/dev/null 2>&1 && echo brew) || echo unknown)"
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

	raw := parseKV(res.Stdout)

	out := map[string]any{
		"system":       raw["system"],
		"kernel":       raw["kernel"],
		"architecture": raw["architecture"],
		"hostname":     raw["hostname"],
		"fqdn":         raw["fqdn"],
		"user_id":      raw["user_id"],
		"pkg_mgr":      raw["pkg_mgr"],
		"os_family":    osFamily(raw["distribution"], raw["distribution_id_like"], raw["system"]),
	}
	if raw["distribution"] != "" {
		out["distribution"] = raw["distribution"]
	}
	if raw["distribution_version"] != "" {
		out["distribution_version"] = raw["distribution_version"]
	}
	if n, err := strconv.Atoi(raw["nproc"]); err == nil {
		out["processor_vcpus"] = n
	}
	if epoch, err := strconv.ParseInt(raw["date_time_epoch"], 10, 64); err == nil {
		out["date_time"] = map[string]any{"epoch": epoch}
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
