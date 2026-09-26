package facts

import (
	"reflect"
	"testing"
)

// Measured from real ansible-core 2.21.4 on this machine:
//
//	"python": {
//	    "executable": ".../venv/bin/python",
//	    "has_sslcontext": true,
//	    "type": "cpython",
//	    "version": {"major": 3, "micro": 7, "minor": 14,
//	                "releaselevel": "final", "serial": 0},
//	    "version_info": [3, 14, 7, "final", 0]
//	},
//	"python_version": "3.14.7"
//
// and the types, from | type_debug: python dict, version dict,
// version_info list, python_version str, major int, serial int,
// version_info[0] int, version_info[3] str.

func TestPythonFacts(t *testing.T) {
	// The probe line this machine actually produced.
	py, ver, ok := pythonFacts(map[string]string{
		"python_probe": "3 14 5 final 0 True cpython 3.14.5 /opt/homebrew/opt/python@3.14/bin/python3.14",
	})
	if !ok {
		t.Fatal("pythonFacts reported nothing for a well-formed probe line")
	}
	if ver != "3.14.5" {
		t.Errorf("python_version = %q, want 3.14.5", ver)
	}
	want := map[string]any{
		"version": map[string]any{
			"major": 3, "minor": 14, "micro": 5,
			"releaselevel": "final", "serial": 0,
		},
		"version_info":   []any{3, 14, 5, "final", 0},
		"executable":     "/opt/homebrew/opt/python@3.14/bin/python3.14",
		"has_sslcontext": true,
		"type":           "cpython",
	}
	if !reflect.DeepEqual(py, want) {
		t.Errorf("python = %#v\nwant %#v", py, want)
	}
	// Real reports exactly these five keys and no others.
	if len(py) != 5 {
		t.Errorf("python has %d keys, want 5", len(py))
	}
}

func TestPythonFactsAbsentWithoutAnInterpreter(t *testing.T) {
	// A host with no Python is a host real cannot reach at all, so
	// there is no reference value to match and inventing one would be
	// worse than the absence.
	if _, _, ok := pythonFacts(map[string]string{"python_probe": ""}); ok {
		t.Error("reported python facts with no interpreter found")
	}
	if _, _, ok := pythonFacts(map[string]string{}); ok {
		t.Error("reported python facts with no probe field at all")
	}
}

func TestPythonFactsKeepsASpaceInTheExecutablePath(t *testing.T) {
	// sys.executable is the only field that can hold a space, which is
	// why it comes last and the split is bounded. An unbounded split
	// would truncate this path and lose its tail.
	py, _, ok := pythonFacts(map[string]string{
		"python_probe": "3 12 1 final 0 False cpython 3.12.1 /Users/a b/py three/bin/python3",
	})
	if !ok {
		t.Fatal("not ok")
	}
	if py["executable"] != "/Users/a b/py three/bin/python3" {
		t.Errorf("executable = %q", py["executable"])
	}
	if py["has_sslcontext"] != false {
		t.Errorf("has_sslcontext = %v, want false", py["has_sslcontext"])
	}
}

func TestPythonFactsRejectsAMalformedLine(t *testing.T) {
	for _, line := range []string{
		"3 14 5 final 0 True cpython 3.14.5",         // eight fields
		"x 14 5 final 0 True cpython 3.14.5 /bin/py", // major not a number
		"3 14 5 final x True cpython 3.14.5 /bin/py", // serial not a number
	} {
		if _, _, ok := pythonFacts(map[string]string{"python_probe": line}); ok {
			t.Errorf("accepted %q", line)
		}
	}
}

func TestPythonFactsTypeIsNullWhenNeitherAttributeExists(t *testing.T) {
	// Real sets type to None in that case, and null is not "".
	py, _, ok := pythonFacts(map[string]string{
		"python_probe": "3 9 0 final 0 True  3.9.0 /usr/bin/python3",
	})
	if !ok {
		t.Fatal("not ok")
	}
	v, present := py["type"]
	if !present {
		t.Fatal("type key missing; real always has one")
	}
	if v != nil {
		t.Errorf("type = %#v, want nil", v)
	}
}

func TestPythonFactsOnThisMachine(t *testing.T) {
	// The whole probe, on whatever machine runs the tests. Any host
	// that can build this package has a Python somewhere on real's
	// fallback list, so an absence here means the discovery loop is
	// broken rather than that the host has none.
	out := runProbeHere(t)
	py, ver, ok := pythonFacts(out)
	if !ok {
		t.Fatalf("the discovery loop found no interpreter; probe said %q", out["python_probe"])
	}
	if ver == "" {
		t.Error("python_version is empty")
	}
	vinfo, _ := py["version_info"].([]any)
	if len(vinfo) != 5 {
		t.Fatalf("version_info = %#v, want five entries", py["version_info"])
	}
	if _, isInt := vinfo[0].(int); !isInt {
		t.Errorf("version_info[0] = %#v, want an int", vinfo[0])
	}
	if _, isStr := vinfo[3].(string); !isStr {
		t.Errorf("version_info[3] = %#v, want a string", vinfo[3])
	}
	if py["executable"] == "" {
		t.Error("executable is empty")
	}
}
