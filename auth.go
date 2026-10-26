package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type session struct {
	user    string
	csrf    string
	expires time.Time
}

type Sessions struct {
	mu       sync.Mutex
	sessions map[string]*session
	failures map[string][]time.Time
	ttl      time.Duration
	secure   bool
}

const sessionCookie = "soju_admin"

func NewSessions(ttl time.Duration, secure bool) *Sessions {
	return &Sessions{
		sessions: map[string]*session{},
		failures: map[string][]time.Time{},
		ttl:      ttl,
		secure:   secure,
	}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Sessions) Create(w http.ResponseWriter, user string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randomToken()
	sess := &session{user: user, csrf: randomToken(), expires: time.Now().Add(s.ttl)}
	s.sessions[id] = sess
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.ttl.Seconds()),
	})
	return sess
}

func (s *Sessions) Get(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[c.Value]
	if sess == nil {
		return nil
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, c.Value)
		return nil
	}
	return sess
}

func (s *Sessions) Destroy(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
}

// Throttled reports whether this client has failed too many logins lately.
func (s *Sessions) Throttled(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute)
	recent := s.failures[ip][:0]
	for _, t := range s.failures[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	s.failures[ip] = recent
	return len(recent) >= 5
}

func (s *Sessions) Fail(ip string) {
	s.mu.Lock()
	s.failures[ip] = append(s.failures[ip], time.Now())
	s.mu.Unlock()
}

func (s *Sessions) Succeed(ip string) {
	s.mu.Lock()
	delete(s.failures, ip)
	s.mu.Unlock()
}

func checkCSRF(sess *session, r *http.Request) bool {
	got := r.Header.Get("X-CSRF-Token")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(sess.csrf)) == 1
}

// clientIP prefers the address Traefik forwards; the panel is only reachable
// through the ingress or a port-forward, so the header can be trusted.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
