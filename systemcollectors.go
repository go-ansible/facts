package facts

import "strings"

// The four fact groups real gathers from a probe whose answer is almost
// always the same on a given platform, and the one group it cannot
// gather at all here. Each is written from real's own collector in
// ansible/module_utils/facts/, because measuring alone would have made
// every one of them look like a Darwin constant: apparmor, lsb and caps
// really do vary, they simply cannot vary on the machine the corpus
// runs on.

// apparmorFacts mirrors ApparmorFactCollector, which tests exactly one
// path and reports "enabled" or "disabled" -- never absent, and never
// anything else.
func apparmorFacts(raw map[string]string) map[string]any {
	status := raw["apparmor_status"]
	if status == "" {
		// A probe that did not answer is not an AppArmor kernel.
		status = "disabled"
	}
	return map[string]any{"status": status}
}

// selinuxFacts mirrors SelinuxFactCollector's FIRST branch, and only
// that one. Real's whole collector is gated on whether the Python
// binding `ansible.module_utils.compat.selinux` imports; with the
// binding missing it reports this exact string and stops, "since there
// is no way to tell if SELinux is enabled or disabled on the system
// without the library".
//
// This port has no Python at all, so that branch is the only one it can
// ever be in, on Linux as much as here. Reading /sys/fs/selinux
// natively would be a different answer, not a better one: it would have
// to pair an "enabled" status with selinux_python_present false, a
// combination real never emits and a playbook branching on the pair has
// never had to handle. Left as the honest answer; a native reader is
// its own increment, with its own decision about the pair.
func selinuxFacts() (map[string]any, bool) {
	return map[string]any{"status": "Missing selinux Python library"}, false
}

// virtualFacts mirrors the GENERIC Virtual base class -- the one real
// falls back to when no per-platform subclass matches. There is no
// darwin.py in ansible/module_utils/facts/virtual/, so a Mac gets these
// four values whether it is bare metal or a guest, which is why
// measuring this machine could not have told them apart.
//
// Linux has a large LinuxVirtual collector that is NOT ported: on a
// Linux guest real names the hypervisor here and this returns the
// generic empties. A disclosed gap, not a silent one.
func virtualFacts() map[string]any {
	return map[string]any{
		"virtualization_type":       "",
		"virtualization_role":       "",
		"virtualization_tech_guest": []any{},
		"virtualization_tech_host":  []any{},
	}
}

// capsFacts mirrors SystemCapabilitiesFactCollector, including the two
// shapes it reports in: the strings "N/A" when capsh did not run, and a
// LIST plus "True"/"False"/"NA" when it did. A playbook that reads
// ansible_system_capabilities sees a str on one host and a list on the
// next, which is real's behaviour and not something to smooth over.
func capsFacts(raw map[string]string) (caps any, enforced any) {
	if raw["caps_rc"] != "0" {
		return "N/A", "N/A"
	}
	// Real seeds enforced with "NA" -- not "N/A" -- and only replaces
	// it inside the "Current:" branch, so a capsh that exits 0 without
	// printing one leaves this spelling behind.
	enforcedStr := "NA"
	list := []any{}
	if line := raw["caps_current"]; line != "" {
		_, after, _ := strings.Cut(line, ":")
		if strings.TrimSpace(after) == "=ep" {
			enforcedStr = "False"
		} else {
			enforcedStr = "True"
			// Python's split('=')[1] is the span between the FIRST
			// and SECOND '=', not everything after the first: a
			// Cut here would swallow a later '=' and report one
			// capability too many.
			if parts := strings.Split(line, "="); len(parts) > 1 {
				for _, c := range strings.Split(parts[1], ",") {
					list = append(list, strings.TrimSpace(c))
				}
			}
		}
	}
	return list, enforcedStr
}

// lsbFacts mirrors LSBFactCollector. The probe has already chosen
// between `lsb_release -a` and /etc/lsb-release and reported the four
// labels, each prefixed with 1 or 0 for whether it was SEEN -- real
// keeps a label that printed an empty value as an empty-valued key, and
// drops one that never appeared, so presence and emptiness are
// different things here.
func lsbFacts(raw map[string]string) map[string]any {
	out := map[string]any{}
	seen := func(key, field string) {
		v, ok := raw[key]
		if !ok || v == "" || v[0] != '1' {
			return
		}
		out[field] = v[1:]
	}
	seen("lsb_id", "id")
	seen("lsb_release", "release")
	seen("lsb_description", "description")
	seen("lsb_codename", "codename")
	// Real derives this only when the dict is non-empty AND carries a
	// release, and it does so BEFORE stripping quotes -- so a quoted
	// release yields a major_release that still has the opening quote,
	// until the strip below reaches it too.
	if len(out) > 0 {
		if rel, ok := out["release"].(string); ok {
			major, _, _ := strings.Cut(rel, ".")
			out["major_release"] = major
		}
	}
	for k, v := range out {
		s, _ := v.(string)
		if s == "" {
			continue
		}
		out[k] = strings.Trim(s, `'"\`)
	}
	return out
}
