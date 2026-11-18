package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpStep   = 30 * time.Second
	totpDigits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret encoded as base32.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// DecodeTOTPSecret decodes a base32 secret, ignoring spaces, case and padding.
func DecodeTOTPSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	s = strings.TrimRight(s, "=")
	key, err := b32.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 TOTP secret: %w", err)
	}
	if len(key) < 10 {
		return nil, fmt.Errorf("TOTP secret too short (%d bytes, want at least 10)", len(key))
	}
	return key, nil
}

// TOTPURI builds the otpauth:// URI that authenticator apps read from a QR code.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", totpDigits, code%1_000_000)
}

// timeStep is the RFC 6238 counter for t. Times before 1970 map to 0.
func timeStep(t time.Time) uint64 {
	sec := t.Unix()
	if sec < 0 {
		return 0
	}
	return uint64(sec) / uint64(totpStep/time.Second) //nolint:gosec // sec is non-negative.
}

// TOTPCode returns the code for key at time t.
func TOTPCode(key []byte, t time.Time) string {
	return hotp(key, timeStep(t))
}

// verifyTOTP checks code against the current step and one step either side
// (clock drift). It returns the matched step so callers can refuse a replay.
func verifyTOTP(key []byte, code string, now time.Time) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	cur := timeStep(now)
	for _, step := range []uint64{cur - 1, cur, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(hotp(key, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}
