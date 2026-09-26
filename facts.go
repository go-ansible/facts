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
    p net_flags "$(ip -o link show dev "$ifc" 2>/dev/null | awk '{if(match($0,/<[^>]*>/)) print substr($0,RSTART+1,RLENGTH-2)}')"
    p net_broadcast "$(ip -4 -o addr show dev "$ifc" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="brd") print $(i+1)}' | head -1)"
  fi
  p net_all_ipv4 "$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | tr '\n' ' ')"
  p net_all_ipv6 "$(ip -6 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -vx -e '::1' -e 'fe80::1%lo0' | tr '\n' ' ')"
  p net_interfaces "$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ' ')"
elif command -v ifconfig >/dev/null 2>&1; then
  ifc=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
  p net_interface "$ifc"
  p net_gateway "$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')"
  p net_interface6 "$(route -n get -inet6 default 2>/dev/null | awk '/interface:/{print $2}')"
  p net_gateway6 "$(route -n get -inet6 default 2>/dev/null | awk '/gateway:/{print $2}')"
  if [ -n "$ifc" ]; then
    p net_cidr "$(ifconfig "$ifc" 2>/dev/null | awk '/inet /{a="";m="";for(i=1;i<=NF;i++){if($i=="inet")a=$(i+1);else if($i=="netmask")m=$(i+1)};if(a!=""){print a" "m;exit}}')"
    p net_macaddress "$(ifconfig "$ifc" 2>/dev/null | awk '/ether /{print $2; exit}')"
    p net_flags "$(ifconfig "$ifc" 2>/dev/null | awk 'NR==1{if(match($0,/<[^>]*>/)) print substr($0,RSTART+1,RLENGTH-2)}')"
    p net_broadcast "$(ifconfig "$ifc" 2>/dev/null | awk '/inet /{b="";for(i=1;i<=NF;i++)if($i=="broadcast")b=$(i+1);print b;exit}')"
    p net_mtu "$(ifconfig "$ifc" 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p' | head -1)"
  fi
  p net_all_ipv4 "$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | tr '\n' ' ')"
  p net_all_ipv6 "$(ifconfig 2>/dev/null | awk '/inet6 /{print $2}' | grep -vx -e '::1' -e 'fe80::1%lo0' | tr '\n' ' ')"
  p net_interfaces "$(ifconfig -l 2>/dev/null)"
fi
# --- portable odds and ends ------------------------------------------
# is_chroot, by real's own algorithm (facts/system/chroot.py): the
# debian_chroot variable wins; otherwise compare / with /proc/1/root,
# which only Linux has; otherwise fall back to "is / inode 2?", with
# the two filesystems real knows use a different root inode.
if [ -n "${debian_chroot:-}" ]; then
  p is_chroot true
else
  root_id=$(stat -c '%i %d' / 2>/dev/null || ls -di / 2>/dev/null | awk '{print $1}')
  proc_id=$(stat -c '%i %d' /proc/1/root/. 2>/dev/null)
  if [ -n "$proc_id" ]; then
    if [ "$root_id" = "$proc_id" ]; then p is_chroot false; else p is_chroot true; fi
  else
    expected=2
    case "$(stat -f --format=%T / 2>/dev/null)" in
      *btrfs*) expected=256 ;;
      *xfs*)   expected=128 ;;
    esac
    if [ "$(echo "$root_id" | awk '{print $1}')" = "$expected" ]; then p is_chroot false; else p is_chroot true; fi
  fi
fi
p fips "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
# Storage identities, from the files real reads. Absent on a host that
# has none, which is every macOS host -- real still reports the facts,
# as an empty string and an empty list.
p hostnqn "$(cat /etc/nvme/hostnqn 2>/dev/null | head -1)"
p iscsi_iqn "$(awk -F= '/^InitiatorName=/{print $2; exit}' /etc/iscsi/initiatorname.iscsi 2>/dev/null)"
p fibre_channel_wwn "$(cat /sys/class/fc_host/*/port_name 2>/dev/null | sed 's/^0x//' | tr '\n' ' ')"
p userspace_bits "$(getconf LONG_BIT 2>/dev/null)"
# --- sysctl, i.e. macOS and the BSDs -----------------------------------
# Linux reports these too, from DMI and /proc/cpuinfo, and not always
# in the same SHAPE: ansible_processor is a string here and a LIST
# there. Guessing at the other platform's shape is worse than leaving
# it alone, so these are emitted only where sysctl answers.
if command -v sysctl >/dev/null 2>&1; then
  p hw_model "$(sysctl -n hw.model 2>/dev/null)"
  p kern_osversion "$(sysctl -n kern.osversion 2>/dev/null)"
  p kern_osrevision "$(sysctl -n kern.osrevision 2>/dev/null)"
  p cpu_brand "$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
fi
# --- the Python interpreter this host has ------------------------------
# Real describes the interpreter that RAN the module. This port runs no
# Python at all, so it reports the interpreter real's own discovery
# would have chosen on this host -- the list below is
# INTERPRETER_PYTHON_FALLBACK from ansible's config/base.yml, in order,
# and the first one that answers wins.
#
# One value therefore differs from real by construction: sys.executable
# is real's OWN interpreter, which on a host running ansible from a venv
# is that venv's python and not the host's. Ours names the host's. A
# playbook reading ansible_python_version -- which is what they read --
# gets the same answer either way.
#
# python_version is asked for directly rather than rebuilt from
# version_info: real uses platform.python_version(), which is parsed
# from sys.version and is not always the three numbers joined by dots.
#
# The fields are space-separated and sys.executable comes LAST, because
# it is the only one that can contain a space.
py_out=
for py_cand in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 /usr/bin/python3 python3; do
  command -v "$py_cand" >/dev/null 2>&1 || continue
  py_out=$("$py_cand" -c 'import platform, sys
try:
    from ssl import create_default_context, SSLContext
    del create_default_context, SSLContext
    has_ssl = "True"
except ImportError:
    has_ssl = "False"
try:
    impl = sys.subversion[0]
except AttributeError:
    try:
        impl = sys.implementation.name
    except AttributeError:
        impl = ""
print("%d %d %d %s %d %s %s %s %s" % (
    sys.version_info[0], sys.version_info[1], sys.version_info[2],
    sys.version_info[3], sys.version_info[4],
    has_ssl, impl, platform.python_version(), sys.executable))
' 2>/dev/null) && [ -n "$py_out" ] && break
  py_out=
done
p python_probe "$py_out"
# --- the four collectors whose answer is a probe, not a constant -------
# Real runs each of these on EVERY platform and always reports the fact,
# so a Darwin host gets "disabled"/{}/"N/A" rather than nothing. Only
# the selection is done here; the parsing real does in Python is done
# in Go, where it can be tested against measured output.
#
# apparmor: real tests one path with os.path.exists and nothing else.
p apparmor_status "$([ -e /sys/kernel/security/apparmor ] && echo enabled || echo disabled)"
# lsb: the lsb_release script first, /etc/lsb-release only if that
# produced nothing at all. Each value is prefixed with 1 or 0 for
# whether the label was SEEN, because real distinguishes a label that
# printed an empty value (the key exists, empty) from one that never
# appeared (no key) -- and an empty p-line cannot say which.
lsb_out=
if lsb_path=$(command -v lsb_release 2>/dev/null); then
  # rc != 0 means real returns {} and never reads the file.
  lsb_out=$("$lsb_path" -a 2>/dev/null) || lsb_out=
fi
lsb_parsed=
if [ -n "$lsb_out" ]; then
  lsb_parsed=$(printf '%s\n' "$lsb_out" | awk '
    {
      if (index($0, ":") == 0) next
      v = substr($0, index($0, ":") + 1)
      gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (index($0, "LSB Version:"))         { rel = v; srel = 1 }
      else if (index($0, "Distributor ID:")) { id = v; sid = 1 }
      else if (index($0, "Description:"))    { desc = v; sdesc = 1 }
      else if (index($0, "Release:"))        { rel = v; srel = 1 }
      else if (index($0, "Codename:"))       { code = v; scode = 1 }
    }
    END { printf "%d%s\n%d%s\n%d%s\n%d%s\n", sid+0, id, srel+0, rel, sdesc+0, desc, scode+0, code }')
fi
if { [ -z "$lsb_parsed" ] || [ "$lsb_parsed" = "0
0
0
0" ]; } && [ -r /etc/lsb-release ]; then
  lsb_parsed=$(awk -F= '
    index($0, "=") == 0 { next }
    {
      v = substr($0, index($0, "=") + 1)
      gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (index($0, "DISTRIB_ID"))               { id = v; sid = 1 }
      else if (index($0, "DISTRIB_RELEASE"))     { rel = v; srel = 1 }
      else if (index($0, "DISTRIB_DESCRIPTION")) { desc = v; sdesc = 1 }
      else if (index($0, "DISTRIB_CODENAME"))    { code = v; scode = 1 }
    }
    END { printf "%d%s\n%d%s\n%d%s\n%d%s\n", sid+0, id, srel+0, rel, sdesc+0, desc, scode+0, code }' \
    /etc/lsb-release 2>/dev/null)
fi
# A missing /etc/lsb-release makes awk exit before END, so nothing at
# all comes back -- and "nothing" cannot be told from a label that was
# seen holding an empty value. Every p-line below must carry a flag.
if [ -z "$lsb_parsed" ]; then lsb_parsed=$(printf '0\n0\n0\n0\n'); fi
p lsb_id "$(printf '%s\n' "$lsb_parsed" | sed -n 1p)"
p lsb_release "$(printf '%s\n' "$lsb_parsed" | sed -n 2p)"
p lsb_description "$(printf '%s\n' "$lsb_parsed" | sed -n 3p)"
p lsb_codename "$(printf '%s\n' "$lsb_parsed" | sed -n 4p)"
# caps: real reports N/A unless capsh ran and exited 0, so the exit
# status is a fact of its own here. It reads the LAST "Current:" line.
caps_rc=-1
caps_out=
if capsh_path=$(command -v capsh 2>/dev/null); then
  caps_out=$("$capsh_path" --print 2>/dev/null); caps_rc=$?
fi
p caps_rc "$caps_rc"
p caps_current "$(printf '%s\n' "$caps_out" | awk '/^Current:/{l=$0} END{print l}')"
# --- resolver, host keys, and the odds and ends -----------------------
p dns_search "$(awk '/^search /{for(i=2;i<=NF;i++) printf "%s ", $i}' /etc/resolv.conf 2>/dev/null)"
p dns_nameservers "$(awk '/^nameserver /{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
p loadavg "$(if [ -r /proc/loadavg ]; then cut -d' ' -f1-3 /proc/loadavg; else sysctl -n vm.loadavg 2>/dev/null | tr -d '{}'; fi)"
# The GECOS field. getent has no macOS equivalent, where the same value
# lives in the directory service under RealName -- and dscl prints it on
# a CONTINUATION line, hence the two-line read.
gecos=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f5)
if [ -z "$gecos" ] && command -v dscl >/dev/null 2>&1; then
  gecos=$(dscl . -read /Users/"$(id -un)" RealName 2>/dev/null | sed -n '2s/^ //p')
fi
p user_gecos "$gecos"
for kt in dsa ecdsa ed25519 rsa; do
  f=/etc/ssh/ssh_host_${kt}_key.pub
  if [ -r "$f" ]; then
    p sshkey_${kt}_type "$(awk '{print $1; exit}' "$f")"
    p sshkey_${kt}_public "$(awk '{print $2; exit}' "$f")"
  fi
done
# The whole ifconfig output, for the per-interface facts. Like the
# environment below it is MULTI-LINE, so it is prefixed and placed
# after every p-line: parseKV stops at the first IFC line. Only when
# there is no "ip" — the parser below reads BSD ifconfig syntax, and
# a Linux host takes the "ip" branch above.
if ! command -v ip >/dev/null 2>&1 && command -v ifconfig >/dev/null 2>&1; then
  ifconfig -a 2>/dev/null | sed 's/^/IFC /'
fi
# The local facts directory (real's facts.d). Each *.fact file becomes
# one entry: executed if it is executable, read otherwise. Multi-line
# like the two sections above, so it is prefixed and kept out of the
# key=value region.
for f in __FACTPATH__/*.fact; do
  [ -r "$f" ] || continue
  b=${f##*/}; b=${b%.fact}
  printf 'FACTD %s %s\n' "$b" "$f"
  if [ -x "$f" ]; then "$f" 2>/dev/null; else cat "$f" 2>/dev/null; fi | sed 's/^/FACTC /'
  printf 'FACTZ\n'
done
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
// Options are the setup module's own knobs, as far as this port
// implements them.
type Options struct {
	// FactPath is real's fact_path: the directory of *.fact files
	// exposed as ansible_local. Empty means real's own default.
	FactPath string
}

// defaultFactPath is where real looks when fact_path is not given.
const defaultFactPath = "/etc/ansible/facts.d"

// Gather collects facts with real's defaults.
func Gather(ctx context.Context, conn remoteexec.Connection) (map[string]any, error) {
	return GatherWith(ctx, conn, Options{})
}

// GatherWith collects facts, honouring the setup module's arguments.
func GatherWith(ctx context.Context, conn remoteexec.Connection, opts Options) (map[string]any, error) {
	factPath := opts.FactPath
	if factPath == "" {
		factPath = defaultFactPath
	}
	script := strings.ReplaceAll(probeScript, "__FACTPATH__", shellQuoteSingle(factPath))
	res, err := conn.Exec(ctx, script, nil)
	if err != nil {
		return nil, fmt.Errorf("facts: gathering: %w", err)
	}
	if res.RC != 0 {
		return nil, fmt.Errorf("facts: gathering: exit %d: %s", res.RC, strings.TrimSpace(res.Stderr))
	}

	// Everything before the first ENV line. An environment variable
	// whose value spans lines would otherwise have its continuation
	// read as a fact — a host could name a fact by exporting one.
	beforeEnv, _, _ := strings.Cut(res.Stdout, "\nENV ")
	// The sections come out in this order: key=value, ifconfig, then
	// the local facts. Cutting from the BACK keeps each one whole.
	beforeLocal, localOut, _ := strings.Cut(beforeEnv, "\nFACTD ")
	facts, ifconfigOut, _ := strings.Cut(beforeLocal, "\nIFC ")
	out := assemble(parseKV(facts), ifconfigOut, parseEnv(res.Stdout))
	out["ansible_local"] = parseLocalFacts(localOut)
	return out, nil
}

// assemble turns what the probe reported into the fact map. It is
// separate from Gather so the mapping can be tested against values
// measured from real Ansible without a connection to run a probe
// over — which is most of what there is to get wrong here.
func assemble(raw map[string]string, ifconfigOut string, env map[string]any) map[string]any {
	out := map[string]any{
		// Real sets both on every gathered host; a playbook reads
		// gather_subset to know what it asked for.
		"_ansible_facts_gathered": true,
		"gather_subset":           []any{"all"},
		"env":                     env,
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
	// A narrower dict built from separate probe values, kept for a host
	// whose interfaces were not parsed at all -- Linux, where the probe
	// collects no ifconfig output. Where they WERE parsed,
	// defaultFromInterface below replaces this with real's own
	// construction, which carries every key of the interface.
	if d4 := defaultIPv4(raw); len(d4) > 0 {
		out["default_ipv4"] = d4
	}
	// Booleans real reports as booleans, not as the strings the probe
	// necessarily speaks in.
	out["is_chroot"] = raw["is_chroot"] == "true"

	// The security and virtualisation collectors. Real reports every one
	// of these on every host, so they are set unconditionally -- see
	// systemcollectors.go for what each one is a port of.
	out["apparmor"] = apparmorFacts(raw)
	if py, pyver, ok := pythonFacts(raw); ok {
		out["python"] = py
		out["python_version"] = pyver
	}
	out["lsb"] = lsbFacts(raw)
	out["selinux"], out["selinux_python_present"] = selinuxFacts()
	out["system_capabilities"], out["system_capabilities_enforced"] = capsFacts(raw)
	for k, v := range virtualFacts() {
		out[k] = v
	}
	out["fips"] = raw["fips"] == "1"

	// Reported even when empty: real reports both as an empty string
	// and the WWN list as an empty list on a host with no such
	// hardware, rather than leaving the keys out.
	out["hostnqn"] = raw["hostnqn"]
	out["iscsi_iqn"] = raw["iscsi_iqn"]
	wwn := splitFields(raw["fibre_channel_wwn"])
	if wwn == nil {
		wwn = []any{}
	}
	out["fibre_channel_wwn"] = wwn

	if b := raw["userspace_bits"]; b != "" {
		out["userspace_bits"] = b
	}
	// hw.model answers TWO facts in real, under both names.
	if m := raw["hw_model"]; m != "" {
		out["model"] = m
		out["product_name"] = m
	}
	for fact, key := range map[string]string{
		"osversion":  "kern_osversion",
		"osrevision": "kern_osrevision",
		"processor":  "cpu_brand",
	} {
		if v := raw[key]; v != "" {
			out[fact] = v
		}
	}

	// module_setup marks that the setup module ran at all. Real sets
	// it unconditionally when it gathers, and a playbook tests it to
	// tell "facts gathered" from "gather_facts: false".
	out["module_setup"] = true

	if list := splitFields(raw["net_all_ipv6"]); len(list) > 0 {
		out["all_ipv6_addresses"] = list
	}
	if g := raw["user_gecos"]; g != "" {
		out["user_gecos"] = g
	}
	if la := parseLoadavg(raw["loadavg"]); la != nil {
		out["loadavg"] = la
	}
	if dns := resolverFacts(raw); dns != nil {
		out["dns"] = dns
	}
	// Real reports each host key twice: the blob itself, and the type
	// that names it -- the two fields of the .pub file.
	for _, kt := range []string{"dsa", "ecdsa", "ed25519", "rsa"} {
		if pub := raw["sshkey_"+kt+"_public"]; pub != "" {
			out["ssh_host_key_"+kt+"_public"] = pub
		}
		if t := raw["sshkey_"+kt+"_type"]; t != "" {
			out["ssh_host_key_"+kt+"_public_keytype"] = t
		}
	}

	ifaces := bsdInterfaces(ifconfigOut)
	// Preferred over the probe-value version below whenever the
	// interface was actually parsed, because this is real's own
	// construction rather than a reimplementation of part of it.
	if d4 := defaultFromInterface(ifaces, raw["net_interface"], raw["net_gateway"], "ipv4"); d4 != nil {
		out["default_ipv4"] = d4
	}
	// default_ipv6 exists only on that path: a host with no parsed
	// interfaces has nothing to merge, and real's Linux collector
	// builds this from sources this port does not read.
	if d6 := defaultFromInterface(ifaces, raw["net_interface6"], raw["net_gateway6"], "ipv6"); d6 != nil {
		out["default_ipv6"] = d6
	}

	// One fact per network interface, keyed by its own name, which is
	// how a playbook reads ansible_facts.en0.ipv4[0].address. Present
	// only where the probe could supply ifconfig output: see
	// bsdInterfaces for why this is not attempted on Linux.
	for name, iface := range ifaces {
		out[name] = iface
	}
	if raw["nproc"] != "" {
		out["processor_vcpus"] = raw["nproc"]
	}
	if raw["date_time_epoch"] != "" {
		out["date_time"] = map[string]any{"epoch": raw["date_time_epoch"]}
	}
	return out
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
	flags := splitFlags(raw["net_flags"])

	macaddress, ifaceType := raw["net_macaddress"], "ether"
	if macaddress == "" {
		macaddress = "unknown"
		// Real decides the type from the interface's FLAGS when there
		// is no hardware address to call it ethernet by: LOOPBACK
		// makes it "loopback", anything else "unknown". Witnessed on
		// both sides -- lo0's own fact dict reports "loopback", a VPN
		// utun interface reports "unknown" -- though not through
		// default_ipv4 itself, which a loopback default route would
		// be needed to produce.
		ifaceType = "unknown"
		if hasFlag(flags, "LOOPBACK") {
			ifaceType = "loopback"
		}
	}
	// The broadcast address is the one the interface DECLARES, and
	// otherwise the one its address and netmask imply. Real never
	// reads the "--> peer" field of a point-to-point interface for
	// this (parse_inet_line in ansible/module_utils/facts/network/
	// generic_bsd.py looks for the "broadcast" keyword and computes
	// the value when it is absent) -- and reading the peer instead
	// agreed with real on the only point-to-point interface available
	// to measure, because a /32 makes the computed broadcast equal
	// the address. On an ordinary /24 tunnel the two answers differ
	// completely: peer 10.8.0.1 against broadcast 10.8.0.255.
	broadcast := raw["net_broadcast"]
	if broadcast == "" {
		b := make(net.IP, len(addr))
		for i := range addr {
			b[i] = addr[i] | ^mask[i]
		}
		broadcast = b.String()
	}

	out := map[string]any{
		"broadcast":  broadcast,
		"address":    addr.String(),
		"netmask":    net.IP(mask).String(),
		"network":    addr.Mask(mask).String(),
		"type":       ifaceType,
		"macaddress": macaddress,
		"flags":      flags,
	}
	for key, value := range map[string]string{
		"interface": raw["net_interface"],
		// device repeats interface. Real carries both, so a playbook
		// written against either keeps working.
		"device":  raw["net_interface"],
		"gateway": raw["net_gateway"],
		// mtu is a STRING, not a number. Measured with type_debug:
		// real reports str where this port reported int, which no
		// comparison of VALUES could show -- both render "1400". The
		// difference is real: `when: mtu > 1400` errors in real and
		// silently succeeded here.
		"mtu": raw["net_mtu"],
	} {
		if value != "" {
			out[key] = value
		}
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

// splitFlags turns the probe's comma-joined interface flags into the
// list real reports, tolerating an absent or empty value: real always
// carries the key, as a list, even when it parsed none.
func splitFlags(raw string) []string {
	if raw == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// parseLoadavg turns the three load figures into real's own dict.
//
// The VALUES can differ from real's on Darwin, and only there: real
// asks the C library, which hands back the kernel's raw fixed-point
// number (9.203125), while a probe running in a shell can only read
// sysctl, which prints two decimals (9.20). On Linux both end up
// reading /proc/loadavg, which has two decimals itself, so both agree.
// The alternative was not reporting the fact at all, which breaks a
// playbook that merely compares it against a threshold.
func parseLoadavg(raw string) map[string]any {
	fields := strings.Fields(raw)
	if len(fields) != 3 {
		return nil
	}
	out := map[string]any{}
	for i, key := range []string{"1m", "5m", "15m"} {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return nil
		}
		out[key] = v
	}
	return out
}

// resolverFacts reports what /etc/resolv.conf declares, in real's
// shape. Absent when the file named neither, rather than an empty
// dict: real was measured with a resolver configured, and what it
// reports without one was not.
func resolverFacts(raw map[string]string) map[string]any {
	search := splitFields(raw["dns_search"])
	servers := splitFields(raw["dns_nameservers"])
	if len(search) == 0 && len(servers) == 0 {
		return nil
	}
	out := map[string]any{}
	if len(search) > 0 {
		out["search"] = search
	}
	if len(servers) > 0 {
		out["nameservers"] = servers
	}
	return out
}
