package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Trusted is a list of networks whose forwarding headers we believe.
type Trusted []netip.Prefix

// Contains reports whether addr belongs to one of the networks.
func (t Trusted) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range t {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// FromTrustedProxy reports whether the TCP peer is a trusted proxy.
func (t Trusted) FromTrustedProxy(r *http.Request) bool {
	a, ok := remoteAddr(r)
	return ok && t.Contains(a)
}

// ClientIP returns the address of the real client. X-Forwarded-For is only
// read when the TCP peer is trusted, and then walked from the right until the
// first address that is not itself a trusted proxy.
func (t Trusted) ClientIP(r *http.Request) string {
	peer, ok := remoteAddr(r)
	if !ok {
		return r.RemoteAddr
	}
	if !t.Contains(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !t.Contains(a) {
			return a.Unmap().String()
		}
	}
	return peer.String()
}

// ProxyIdentity reads the user set by an authenticating proxy (Authelia's
// Remote-User, oauth2-proxy's X-Auth-Request-User, ...). It returns ok=false
// when the request did not come through a trusted proxy or has no user.
type ProxyIdentity struct {
	Trusted     Trusted
	UserHeader  string
	GroupHeader string
	AdminGroup  string // empty: every proxied user is admin
}

// Identify returns the user name and role for r.
func (p ProxyIdentity) Identify(r *http.Request) (string, Role, bool) {
	if !p.Trusted.FromTrustedProxy(r) {
		return "", "", false
	}
	user := strings.TrimSpace(r.Header.Get(p.UserHeader))
	if !userNameRe.MatchString(user) {
		return "", "", false
	}
	if p.AdminGroup == "" {
		return user, RoleAdmin, true
	}
	for _, g := range strings.Split(r.Header.Get(p.GroupHeader), ",") {
		if strings.TrimSpace(g) == p.AdminGroup {
			return user, RoleAdmin, true
		}
	}
	return user, RoleViewer, true
}
