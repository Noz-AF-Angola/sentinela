// Package auth implements Sentinela's own login: a small users file with
// bcrypt hashes and optional TOTP, server-side sessions, login throttling, and
// the alternative "trusted proxy" mode for Authelia / oauth2-proxy setups.
package auth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role decides what a user may do.
type Role string

const (
	// RoleAdmin can read everything and make changes.
	RoleAdmin Role = "admin"
	// RoleViewer can only read.
	RoleViewer Role = "viewer"
)

// ParseRole turns a string into a Role.
func ParseRole(s string) (Role, error) {
	switch Role(strings.ToLower(strings.TrimSpace(s))) {
	case RoleAdmin:
		return RoleAdmin, nil
	case RoleViewer:
		return RoleViewer, nil
	}
	return "", fmt.Errorf("unknown role %q (want admin or viewer)", s)
}

// User is one entry of the users file.
type User struct {
	Name string
	Role Role
	hash []byte
	totp []byte
}

// HasTOTP reports whether the user must enter a one-time code.
func (u *User) HasTOTP() bool { return len(u.totp) > 0 }

var userNameRe = regexp.MustCompile(`^[a-zA-Z0-9._@-]{1,64}$`)

// BcryptCost is the work factor used by HashPassword.
const BcryptCost = 12

// HashPassword returns a bcrypt hash suitable for the users file.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	if len(password) > 72 {
		return "", errors.New("password must be at most 72 bytes (bcrypt limit)")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	return string(h), err
}

// ParseUsers reads the users file. One user per line:
//
//	name:role:bcrypt-hash[:totp-secret-base32]
//
// Blank lines and lines starting with # are ignored.
func ParseUsers(r io.Reader) (map[string]*User, error) {
	users := map[string]*User{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 || len(parts) > 4 {
			return nil, fmt.Errorf("users file line %d: want name:role:hash[:totp]", n)
		}
		name := parts[0]
		if !userNameRe.MatchString(name) {
			return nil, fmt.Errorf("users file line %d: invalid user name", n)
		}
		if _, dup := users[name]; dup {
			return nil, fmt.Errorf("users file line %d: duplicate user %q", n, name)
		}
		role, err := ParseRole(parts[1])
		if err != nil {
			return nil, fmt.Errorf("users file line %d: %w", n, err)
		}
		if _, err := bcrypt.Cost([]byte(parts[2])); err != nil {
			return nil, fmt.Errorf("users file line %d: not a bcrypt hash", n)
		}
		u := &User{Name: name, Role: role, hash: []byte(parts[2])}
		if len(parts) == 4 && parts[3] != "" {
			key, err := DecodeTOTPSecret(parts[3])
			if err != nil {
				return nil, fmt.Errorf("users file line %d: %w", n, err)
			}
			u.totp = key
		}
		users[name] = u
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, errors.New("users file has no users")
	}
	return users, nil
}

// LoadUsersFile reads and parses a users file from disk.
func LoadUsersFile(path string) (map[string]*User, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the operator's configuration.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ParseUsers(f)
}

// ErrInvalidCredentials is returned for any failed login, whatever the cause,
// so the response does not tell an attacker which part was wrong.
var ErrInvalidCredentials = errors.New("invalid credentials")

// dummyHash is compared against when the user does not exist, so that a
// missing user takes as long to reject as a wrong password.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("sentinela-timing-equaliser"), BcryptCost)

// Directory checks credentials against the users file.
type Directory struct {
	users map[string]*User

	mu       sync.Mutex
	lastStep map[string]uint64 // last accepted TOTP step per user (replay guard)
	now      func() time.Time
}

// NewDirectory wraps a parsed users map.
func NewDirectory(users map[string]*User) *Directory {
	return &Directory{users: users, lastStep: map[string]uint64{}, now: time.Now}
}

// Authenticate verifies name, password and, when configured, the TOTP code.
func (d *Directory) Authenticate(name, password, code string) (*User, error) {
	u, ok := d.users[name]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword(u.hash, []byte(password)) != nil {
		return nil, ErrInvalidCredentials
	}
	if u.HasTOTP() {
		step, ok := verifyTOTP(u.totp, code, d.now())
		if !ok {
			return nil, ErrInvalidCredentials
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if last, seen := d.lastStep[name]; seen && step <= last {
			return nil, ErrInvalidCredentials
		}
		d.lastStep[name] = step
	}
	return u, nil
}
