package facts

import (
	"strconv"
	"strings"
)

// pythonFacts mirrors PythonFactCollector plus platform.py's
// python_version, from the one line the probe reports.
//
// Real describes the interpreter that ran the module. This port runs no
// Python, so the probe walked real's own INTERPRETER_PYTHON_FALLBACK
// list and asked the first interpreter that answered. The question a
// playbook asks -- what Python does this host have -- gets the same
// answer; "executable" does not, because real's is its own, which on a
// host running ansible from a venv is that venv's rather than the
// host's.
//
// A host with no Python at all gets neither fact. Real cannot reach that
// host at all, so there is no reference value to match; reporting
// something would be inventing one.
func pythonFacts(raw map[string]string) (python map[string]any, version string, ok bool) {
	line := raw["python_probe"]
	if line == "" {
		return nil, "", false
	}
	// Nine fields, and sys.executable is the last because it is the
	// only one that may contain a space.
	f := strings.SplitN(line, " ", 9)
	if len(f) != 9 {
		return nil, "", false
	}
	major, err1 := strconv.Atoi(f[0])
	minor, err2 := strconv.Atoi(f[1])
	micro, err3 := strconv.Atoi(f[2])
	serial, err4 := strconv.Atoi(f[4])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil, "", false
	}
	releaselevel := f[3]
	python = map[string]any{
		"version": map[string]any{
			"major":        major,
			"minor":        minor,
			"micro":        micro,
			"releaselevel": releaselevel,
			"serial":       serial,
		},
		// list(sys.version_info): five entries, the fourth a string.
		"version_info":   []any{major, minor, micro, releaselevel, serial},
		"executable":     f[8],
		"has_sslcontext": f[5] == "True",
	}
	// Real sets type to None when neither sys.subversion nor
	// sys.implementation exists. No interpreter this port can reach is
	// that old, but an empty field is the probe saying "neither", and
	// null is what real would report.
	if f[6] == "" {
		python["type"] = nil
	} else {
		python["type"] = f[6]
	}
	return python, f[7], true
}
