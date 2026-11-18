package validate

import "testing"

func TestTarget(t *testing.T) {
	cases := []struct {
		in, value, scope string
		ok               bool
	}{
		{"192.0.2.10", "192.0.2.10", ScopeIP, true},
		{" 2001:db8::1 ", "2001:db8::1", ScopeIP, true},
		{"::ffff:192.0.2.1", "192.0.2.1", ScopeIP, true},
		{"198.51.100.7/24", "198.51.100.0/24", ScopeRange, true},
		{"fe80::1%eth0", "", "", false},
		{"192.0.2.300", "", "", false},
		{"-v", "", "", false},
		{"", "", "", false},
		{"192.0.2.1; rm -rf /", "", "", false},
	}
	for _, c := range cases {
		v, s, err := Target(c.in)
		if (err == nil) != c.ok || v != c.value || s != c.scope {
			t.Errorf("Target(%q) = %q, %q, %v", c.in, v, s, err)
		}
	}
	if _, err := IP("192.0.2.0/24"); err == nil {
		t.Error("IP accepted a range")
	}
}

func TestDuration(t *testing.T) {
	good := map[string]string{"4h": "4h", "30m": "30m", "7d": "168h", "90s": "90s"}
	for in, want := range good {
		got, err := Duration(in)
		if err != nil || got != want {
			t.Errorf("Duration(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0h", "4", "1w", "-4h", "4h30m", "9999d"} {
		if _, err := Duration(bad); err == nil {
			t.Errorf("Duration(%q) accepted", bad)
		}
	}
	if e, err := Expiration(""); err != nil || e != "" {
		t.Errorf("empty expiration: %q %v", e, err)
	}
	if _, err := Expiration("--yes"); err == nil {
		t.Error("Expiration accepted a flag")
	}
}

func TestNames(t *testing.T) {
	if _, err := HubName("crowdsecurity/appsec-virtual-patching"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"-x", "../../etc/passwd", "a b", "", "foo;bar"} {
		if _, err := HubName(bad); err == nil {
			t.Errorf("HubName(%q) accepted", bad)
		}
	}
	if _, err := AllowlistName("office_ips"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"-d", "a/b", "", "x y"} {
		if _, err := AllowlistName(bad); err == nil {
			t.Errorf("AllowlistName(%q) accepted", bad)
		}
	}
	if v, _ := DecisionType(""); v != "ban" {
		t.Errorf("default decision type = %q", v)
	}
	if _, err := DecisionType("Ban!"); err == nil {
		t.Error("bad decision type accepted")
	}
	if !IsHubType("appsec-rules") || IsHubType("bouncers") {
		t.Error("IsHubType")
	}
}

func TestText(t *testing.T) {
	if _, err := Text("line\nbreak", 50); err == nil {
		t.Error("control characters accepted")
	}
	if _, err := Text("abcdef", 3); err == nil {
		t.Error("length not enforced")
	}
	if v, err := Text("  trusted office  ", 50); err != nil || v != "trusted office" {
		t.Errorf("Text = %q %v", v, err)
	}
}
