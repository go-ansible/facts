package facts

import (
	"context"
	"strings"
	"testing"
)

// ⛔ A fact VALUE can contain a newline, and the probe's output is parsed
// line by line — so a target can make the parser see an extra
// `key=value`. /etc/os-release is the reachable route: the probe SOURCES
// it and emits $ID, $VERSION_ID, $ID_LIKE and $VERSION_CODENAME, and a
// host that controls that file controls those values.
//
//	parseKV("distribution='Debian\nconnection=ssh'")
//	  -> map[connection:ssh distribution:Debian]
//
// That injection is INERT, and this test is why it stays that way:
// assemble names every fact it builds (raw["system"], raw["kernel"], …)
// and never ranges over the parsed map. A refactor to
// `for k, v := range raw` would hand a managed host the ability to set
// arbitrary ansible_* variables on the controller — including the
// connection variables, which decide where later tasks run.
//
// The comment in Gather already guards the ENV route the same way, by
// cutting the stream before the first ENV line. This covers the other
// one.
func TestAnInjectedFactKeyIsNotCarried(t *testing.T) {
	raw := parseKV("system='Linux'\ndistribution='Debian\nansible_connection=ssh\nconnection=ssh\nevil=1'")

	// The parser really is injectable: that is the premise, not a bug
	// this test is asserting away.
	if _, ok := raw["evil"]; !ok {
		t.Fatal("the premise no longer holds: parseKV did not take the injected key, " +
			"so this test is no longer measuring what it claims")
	}

	out := assemble(raw, "", nil)
	for _, k := range []string{"evil", "connection", "ansible_connection", "ansible_evil"} {
		if _, ok := out[k]; ok {
			t.Errorf("an injected fact key %q reached the facts: a managed host can name "+
				"a variable on the controller", k)
		}
	}
	// The control: a LEGITIMATE key does come through, so the absences
	// above are the allow-list and not an empty result.
	//
	// The keys here are UNPREFIXED -- the engine adds `ansible_` when it
	// injects them into the variable store, which is precisely why an
	// injected `connection` would land as `ansible_connection` and
	// decide where later tasks run.
	if out["system"] != "Linux" {
		t.Fatalf("control failed: a real fact did not come through either (%v), "+
			"so this test proves nothing", out["system"])
	}
}

// And end to end, through Gather, since the parser is only half the path.
func TestAnInjectedFactKeyIsNotCarriedEndToEnd(t *testing.T) {
	stdout := "system='Linux'\nhostname='h1'\ndistribution='Debian\nconnection=ssh\nevil=1'\n"
	got, err := Gather(context.Background(), scriptedConn{stdout: stdout})
	if err != nil {
		t.Fatal(err)
	}
	for k := range got {
		if strings.Contains(k, "evil") || k == "ansible_connection" || k == "connection" {
			t.Errorf("an injected key reached the gathered facts: %q", k)
		}
	}
	if got["system"] != "Linux" {
		t.Fatalf("control failed: no real fact came through either (%v)", got["system"])
	}
}
