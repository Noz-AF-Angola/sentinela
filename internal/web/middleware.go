package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Noz-AF-Angola/sentinela/internal/auth"
)

type handler func(http.ResponseWriter, *http.Request, *auth.Session)

func (s *Server) setCookie(w http.ResponseWriter, sess *auth.Session) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is configurable for VPN-only plain HTTP; HttpOnly and SameSite are set.
		Name: s.cookie, Value: sess.ID, Path: "/", HttpOnly: true,
		Secure: s.opt.CookieSecure, SameSite: http.SameSiteStrictMode,
		Expires: sess.Expires,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // see setCookie.
		Name: s.cookie, Value: "", Path: "/", HttpOnly: true,
		Secure: s.opt.CookieSecure, SameSite: http.SameSiteStrictMode,
		MaxAge: -1, Expires: time.Unix(0, 0),
	})
}

func (s *Server) currentSession(r *http.Request) *auth.Session {
	c, err := r.Cookie(s.cookie)
	if err != nil {
		return nil
	}
	return s.sessions.Get(c.Value)
}

// authed resolves the session (or the proxy identity), and on unsafe methods
// checks the form's CSRF token.
func (s *Server) authed(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := s.currentSession(r)
		if s.opt.Proxy != nil {
			user, role, ok := s.opt.Proxy.Identify(r)
			if !ok {
				s.errorPage(w, r, nil, http.StatusUnauthorized,
					"This request did not come through the authenticating proxy.")
				return
			}
			if sess == nil || !sess.Proxy || sess.User != user || sess.Role != role {
				if sess != nil {
					s.sessions.Delete(sess.ID)
				}
				sess = s.sessions.Create(user, role, true)
				s.setCookie(w, sess)
			}
		}
		if sess == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			s.errorPage(w, r, nil, http.StatusUnauthorized, "Your session has expired. Please log in again.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				s.errorPage(w, r, sess, http.StatusBadRequest, "The form could not be read.")
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
				s.errorPage(w, r, sess, http.StatusForbidden, "The form token is missing or wrong. Reload the page and try again.")
				return
			}
		}
		h(w, r, sess)
	})
}

func (s *Server) canEdit(sess *auth.Session) bool {
	return sess != nil && sess.Role == auth.RoleAdmin && !s.opt.ReadOnly
}

func (s *Server) admin(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
		if !s.canEdit(sess) {
			s.errorPage(w, r, sess, http.StatusForbidden, "Your account can only view, not change anything.")
			return
		}
		h(w, r, sess)
	}
}

// safeNext only allows local paths as login redirect targets.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.HasPrefix(next, "/\\") || strings.ContainsAny(next, "\r\n") {
		return "/"
	}
	return next
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.opt.Proxy != nil || s.currentSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, http.StatusOK, safeNext(r.URL.Query().Get("next")), "", "")
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, next, user, msg string) {
	s.render(w, status, "login", &pageData{Title: "Log in", Data: map[string]string{
		"Next": next, "User": user, "Error": msg,
	}})
}

var errThrottled = errors.New("too many attempts")

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if s.opt.Directory == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, http.StatusBadRequest, "/", "", "The form could not be read.")
		return
	}
	user := strings.TrimSpace(r.PostFormValue("username"))
	next := safeNext(r.PostFormValue("next"))
	ip := s.opt.Trusted.ClientIP(r)

	var err error
	var u *auth.User
	if !s.ipLimit.Allowed(ip) || !s.usrLimit.Allowed(user) {
		err = errThrottled
	} else {
		u, err = s.opt.Directory.Authenticate(user, r.PostFormValue("password"), r.PostFormValue("code"))
	}
	if err != nil {
		if !errors.Is(err, errThrottled) {
			s.ipLimit.Fail(ip)
			s.usrLimit.Fail(user)
		}
		s.log.Warn("login failed", "user", user, "client_ip", ip, "reason", err.Error())
		msg := "Wrong user name, password or code."
		if errors.Is(err, errThrottled) {
			msg = "Too many failed attempts. Wait 15 minutes and try again."
		}
		s.renderLogin(w, http.StatusUnauthorized, next, user, msg)
		return
	}
	s.ipLimit.Reset(ip)
	s.usrLimit.Reset(user)
	if old := s.currentSession(r); old != nil {
		s.sessions.Delete(old.ID)
	}
	sess := s.sessions.Create(u.Name, u.Role, false)
	s.setCookie(w, sess)
	s.log.Info("login", "user", u.Name, "role", string(u.Role), "client_ip", ip)
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // next went through safeNext: local paths only.
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	s.sessions.Delete(sess.ID)
	s.clearCookie(w)
	s.log.Info("logout", "user", sess.User)
	if s.opt.Proxy != nil {
		if s.opt.LogoutURL != "" {
			http.Redirect(w, r, s.opt.LogoutURL, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
