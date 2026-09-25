package facts

import (
	"reflect"
	"testing"
)

// Real's shape, measured: three floats under 1m/5m/15m.
func TestParseLoadavg(t *testing.T) {
	got := parseLoadavg(" 8.62 9.31 8.88 ")
	want := map[string]any{"1m": 8.62, "5m": 9.31, "15m": 8.88}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	// /proc/loadavg's own spelling, which is what Linux supplies.
	if got := parseLoadavg("0.52 0.58 0.59"); got["1m"] != 0.52 || got["15m"] != 0.59 {
		t.Fatalf("got %#v", got)
	}
	for _, bad := range []string{"", "1.0 2.0", "a b c", "1 2 3 4"} {
		if got := parseLoadavg(bad); got != nil {
			t.Errorf("parseLoadavg(%q) = %#v, want nil", bad, got)
		}
	}
}

func TestResolverFacts(t *testing.T) {
	got := resolverFacts(map[string]string{
		"dns_search":      "example.org example.net ",
		"dns_nameservers": "203.0.113.53 203.0.113.54 ",
	})
	want := map[string]any{
		"search":      []any{"example.org", "example.net"},
		"nameservers": []any{"203.0.113.53", "203.0.113.54"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	// Neither declared: absent, not an empty dict. Real was measured
	// WITH a resolver configured; what it reports without one was not,
	// so nothing is asserted about that case by inventing a value.
	if got := resolverFacts(map[string]string{}); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	// One without the other still reports what it has.
	got = resolverFacts(map[string]string{"dns_nameservers": "203.0.113.53 "})
	if _, ok := got["search"]; ok {
		t.Errorf("search present with none declared: %#v", got)
	}
	if !reflect.DeepEqual(got["nameservers"], []any{"203.0.113.53"}) {
		t.Errorf("nameservers = %#v", got["nameservers"])
	}
}

// The two fields of a .pub file become two facts, and real names them
// so that the blob keeps the plain name and the algorithm gets the
// longer one. Values here are fabricated: a host's real keys are not
// something to put in a repository.
func TestSSHHostKeyFactNames(t *testing.T) {
	out := assemble(map[string]string{
		"sshkey_ed25519_type":   "ssh-ed25519",
		"sshkey_ed25519_public": "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
		"sshkey_rsa_type":       "ssh-rsa",
		"sshkey_rsa_public":     "AAAAB3NzaC1yc2EAAAADAQABAAABgQEXAMPLE",
	}, "", nil)
	for key, want := range map[string]any{
		"ssh_host_key_ed25519_public":         "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
		"ssh_host_key_ed25519_public_keytype": "ssh-ed25519",
		"ssh_host_key_rsa_public":             "AAAAB3NzaC1yc2EAAAADAQABAAABgQEXAMPLE",
		"ssh_host_key_rsa_public_keytype":     "ssh-rsa",
	} {
		if out[key] != want {
			t.Errorf("%s = %#v, want %#v", key, out[key], want)
		}
	}
	// A key type the host does not have produces no fact at all.
	for _, absent := range []string{"ssh_host_key_dsa_public", "ssh_host_key_ecdsa_public_keytype"} {
		if _, ok := out[absent]; ok {
			t.Errorf("%s present although the host has no such key", absent)
		}
	}
}

// module_setup says the setup module ran, which is how a playbook
// tells gathered facts from gather_facts: false. Real sets it
// unconditionally, so it is there even for a host that answered
// almost nothing.
func TestModuleSetupIsAlwaysReported(t *testing.T) {
	if out := assemble(map[string]string{}, "", nil); out["module_setup"] != true {
		t.Fatalf("module_setup = %#v, want true", out["module_setup"])
	}
}

func TestGecosAndIPv6List(t *testing.T) {
	out := assemble(map[string]string{
		"user_gecos":   "A Person",
		"net_all_ipv6": "fe80::dead:beef%en0 2001:db8::1 ",
	}, "", nil)
	if out["user_gecos"] != "A Person" {
		t.Errorf("user_gecos = %#v", out["user_gecos"])
	}
	if want := []any{"fe80::dead:beef%en0", "2001:db8::1"}; !reflect.DeepEqual(out["all_ipv6_addresses"], want) {
		t.Errorf("all_ipv6_addresses = %#v, want %#v", out["all_ipv6_addresses"], want)
	}
	// An empty value reports nothing rather than an empty list.
	bare := assemble(map[string]string{}, "", nil)
	if _, ok := bare["user_gecos"]; ok {
		t.Error("user_gecos present with none reported")
	}
	if _, ok := bare["all_ipv6_addresses"]; ok {
		t.Error("all_ipv6_addresses present with none reported")
	}
}

// hw.model answers TWO facts in real, under both names. Measured on a
// Mac16,5; the value here is real's own shape with a different model.
func TestSysctlDerivedFacts(t *testing.T) {
	out := assemble(map[string]string{
		"hw_model":        "MacExample1,1",
		"kern_osversion":  "25G83",
		"kern_osrevision": "199506",
		"cpu_brand":       "Apple M4 Max",
		"userspace_bits":  "64",
	}, "", nil)
	for k, want := range map[string]any{
		"model":          "MacExample1,1",
		"product_name":   "MacExample1,1",
		"osversion":      "25G83",
		"osrevision":     "199506",
		"processor":      "Apple M4 Max",
		"userspace_bits": "64",
	} {
		if out[k] != want {
			t.Errorf("%s = %#v, want %#v", k, out[k], want)
		}
	}
	// A host whose sysctl answered none of them reports none of them,
	// rather than empty strings. Linux is such a host: it has these
	// facts in real, from other sources and -- for processor -- in a
	// different SHAPE, a list rather than a string.
	bare := assemble(map[string]string{}, "", nil)
	for _, k := range []string{"model", "product_name", "osversion", "osrevision", "processor", "userspace_bits"} {
		if _, ok := bare[k]; ok {
			t.Errorf("%s present although sysctl answered nothing", k)
		}
	}
}

// Real reports these two as booleans. The probe can only speak in
// strings, so the conversion is the thing under test -- and a missing
// value must read as false, not as absent: real always reports both.
func TestChrootAndFipsAreBooleans(t *testing.T) {
	for _, tc := range []struct {
		raw          map[string]string
		chroot, fips bool
	}{
		{map[string]string{"is_chroot": "true", "fips": "1"}, true, true},
		{map[string]string{"is_chroot": "false", "fips": "0"}, false, false},
		{map[string]string{}, false, false},
	} {
		out := assemble(tc.raw, "", nil)
		if out["is_chroot"] != tc.chroot {
			t.Errorf("is_chroot for %v = %#v, want %v", tc.raw, out["is_chroot"], tc.chroot)
		}
		if out["fips"] != tc.fips {
			t.Errorf("fips for %v = %#v, want %v", tc.raw, out["fips"], tc.fips)
		}
	}
}

// Real reports these three even on a host that has none of the
// hardware: two empty strings and an empty list, not absent keys.
func TestStorageIdentitiesAreAlwaysReported(t *testing.T) {
	out := assemble(map[string]string{}, "", nil)
	if out["hostnqn"] != "" {
		t.Errorf("hostnqn = %#v, want \"\"", out["hostnqn"])
	}
	if out["iscsi_iqn"] != "" {
		t.Errorf("iscsi_iqn = %#v, want \"\"", out["iscsi_iqn"])
	}
	if got, ok := out["fibre_channel_wwn"].([]any); !ok || len(got) != 0 {
		t.Errorf("fibre_channel_wwn = %#v, want an empty list", out["fibre_channel_wwn"])
	}
	// And carried through when the host does have them.
	out = assemble(map[string]string{
		"hostnqn":           "nqn.2014-08.org.nvmexpress:uuid:00000000-0000-0000-0000-000000000000",
		"iscsi_iqn":         "iqn.1993-08.org.debian:01:0000000000",
		"fibre_channel_wwn": "10000000c9000000 10000000c9000001 ",
	}, "", nil)
	if out["hostnqn"] == "" || out["iscsi_iqn"] == "" {
		t.Errorf("hostnqn/iscsi_iqn dropped: %#v %#v", out["hostnqn"], out["iscsi_iqn"])
	}
	if !reflect.DeepEqual(out["fibre_channel_wwn"], []any{"10000000c9000000", "10000000c9000001"}) {
		t.Errorf("fibre_channel_wwn = %#v", out["fibre_channel_wwn"])
	}
}
