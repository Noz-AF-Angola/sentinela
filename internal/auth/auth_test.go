package auth

import (
	"encoding/hex"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA1 column (8 digits there; we compare the last 6).
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	vectors := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for ts, want := range vectors {
		got := TOTPCode(key, time.Unix(ts, 0))
		if got != want[2:] {
			t.Errorf("t=%d got %s want %s", ts, got, want[2:])
		}
	}
}

func TestTOTPSecretRoundTrip(t *testing.T) {
	s, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	k, err := DecodeTOTPSecret(strings.ToLower(s))
	if err != nil || len(k) != 20 {
		t.Fatalf("decode: %v len=%d", err, len(k))
	}
	if _, err := DecodeTOTPSecret("AAAA"); err == nil {
		t.Error("short secret accepted")
	}
	uri := TOTPURI("Sentinela", "alice", s)
	if !strings.HasPrefix(uri, "otpauth://totp/Sentinela:alice?") || !strings.Contains(uri, "secret="+s) {
		t.Errorf("uri = %s", uri)
	}
}

func usersFile(t *testing.T, withTOTP bool) (string, []byte) {
	t.Helper()
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString("3132333435363738393031323334353637383930")
	line := "alice:admin:" + h
	if withTOTP {
		line += ":" + b32.EncodeToString(key)
	}
	return "# comment\n\n" + line + "\nbob:viewer:" + h + "\n", key
}

func TestParseUsers(t *testing.T) {
	content, _ := usersFile(t, true)
	users, err := ParseUsers(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users["alice"].Role != RoleAdmin || !users["alice"].HasTOTP() || users["bob"].HasTOTP() {
		t.Fatalf("unexpected users: %+v", users)
	}
	bad := []string{
		"",
		"alice:admin",
		"alice:root:$2a$12$abc",
		"alice:admin:plaintext",
		"al ice:admin:$2a$12$abc",
	}
	for _, b := range bad {
		if _, err := ParseUsers(strings.NewReader(b)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
	dup := content + content
	if _, err := ParseUsers(strings.NewReader(dup)); err == nil {
		t.Error("duplicate users accepted")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password accepted")
	}
}

func TestAuthenticate(t *testing.T) {
	content, key := usersFile(t, true)
	users, _ := ParseUsers(strings.NewReader(content))
	d := NewDirectory(users)
	now := time.Unix(1700000000, 0)
	d.now = func() time.Time { return now }

	if _, err := d.Authenticate("bob", "correct horse battery", ""); err != nil {
		t.Errorf("bob: %v", err)
	}
	if _, err := d.Authenticate("bob", "wrong password!!", ""); err != ErrInvalidCredentials {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := d.Authenticate("nobody", "correct horse battery", ""); err != ErrInvalidCredentials {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := d.Authenticate("alice", "correct horse battery", ""); err != ErrInvalidCredentials {
		t.Error("alice logged in without TOTP")
	}
	code := TOTPCode(key, now)
	if _, err := d.Authenticate("alice", "correct horse battery", code); err != nil {
		t.Errorf("alice with code: %v", err)
	}
	if _, err := d.Authenticate("alice", "correct horse battery", code); err != ErrInvalidCredentials {
		t.Error("TOTP code replay accepted")
	}
	now = now.Add(30 * time.Second)
	if _, err := d.Authenticate("alice", "correct horse battery", TOTPCode(key, now)); err != nil {
		t.Errorf("next step: %v", err)
	}
}

func TestStore(t *testing.T) {
	s := NewStore(time.Hour)
	now := time.Unix(1700000000, 0)
	s.now = func() time.Time { return now }
	sess := s.Create("alice", RoleAdmin, false)
	if sess.ID == "" || sess.CSRF == "" || sess.ID == sess.CSRF {
		t.Fatal("bad tokens")
	}
	s.AddFlash(sess.ID, "ok", "done")
	if got := s.PopFlashes(sess.ID); len(got) != 1 || got[0].Text != "done" {
		t.Errorf("flashes = %v", got)
	}
	if len(s.PopFlashes(sess.ID)) != 0 {
		t.Error("flashes not cleared")
	}
	if s.Get(sess.ID) == nil {
		t.Fatal("session missing")
	}
	now = now.Add(2 * time.Hour)
	if s.Get(sess.ID) != nil {
		t.Error("expired session returned")
	}
	if s.Get("") != nil {
		t.Error("empty id returned a session")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allowed("k") {
			t.Fatalf("blocked after %d", i)
		}
		l.Fail("k")
	}
	if l.Allowed("k") {
		t.Error("not blocked after 3 failures")
	}
	now = now.Add(2 * time.Minute)
	if !l.Allowed("k") {
		t.Error("still blocked after window")
	}
	l.Fail("k")
	l.Reset("k")
	if !l.Allowed("k") {
		t.Error("reset did not clear")
	}
}

func TestClientIPAndProxy(t *testing.T) {
	trusted := Trusted{netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:4000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := trusted.ClientIP(r); got != "203.0.113.9" {
		t.Errorf("untrusted peer: XFF used, got %s", got)
	}
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Set("X-Forwarded-For", "198.51.100.66, 192.0.2.4, 10.0.0.5")
	if got := trusted.ClientIP(r); got != "192.0.2.4" {
		t.Errorf("trusted peer: got %s", got)
	}

	p := ProxyIdentity{Trusted: trusted, UserHeader: "Remote-User", GroupHeader: "Remote-Groups", AdminGroup: "admins"}
	r.Header.Set("Remote-User", "alice")
	r.Header.Set("Remote-Groups", "dev, admins")
	if u, role, ok := p.Identify(r); !ok || u != "alice" || role != RoleAdmin {
		t.Errorf("identify = %s %s %v", u, role, ok)
	}
	r.Header.Set("Remote-Groups", "dev")
	if _, role, _ := p.Identify(r); role != RoleViewer {
		t.Errorf("non-admin got %s", role)
	}
	r.RemoteAddr = "203.0.113.9:4000"
	if _, _, ok := p.Identify(r); ok {
		t.Error("header trusted from an untrusted peer")
	}
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Set("Remote-User", "bad user\n")
	if _, _, ok := p.Identify(r); ok {
		t.Error("invalid user name accepted")
	}
}
