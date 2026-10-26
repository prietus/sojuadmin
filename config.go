package main

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"codeberg.org/emersion/go-scfg"
)

// ConfigCheck is the result of validating a soju config file before it is
// written to the ConfigMap. Errors block saving; warnings don't.
type ConfigCheck struct {
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// Directives understood by soju v0.11 and their accepted parameter counts
// (max -1 = unbounded).
var sojuDirectives = map[string][2]int{
	"listen":                {1, 1},
	"hostname":              {1, 1},
	"title":                 {1, 1},
	"icon":                  {1, 1},
	"tls":                   {2, 2},
	"db":                    {2, 2},
	"message-store":         {1, 2},
	"log":                   {1, 2},
	"file-upload":           {1, 2},
	"http-origin":           {1, -1},
	"http-ingress":          {1, 1},
	"accept-proxy-ip":       {1, -1},
	"accept-proxy-unix":     {1, 1},
	"max-user-networks":     {1, 1},
	"motd":                  {1, 1},
	"upstream-user-ip":      {1, -1},
	"disable-inactive-user": {1, 1},
	"message-expiry":        {1, 1},
	"enable-user-on-auth":   {1, 1},
	"auth":                  {1, 2},
	"client-cert-auth":      {1, 1},
}

// soju decodes the config strictly: unknown directives and repeated
// directives (other than these) make it refuse to start.
var repeatableDirectives = map[string]bool{"listen": true, "auth": true}

var listenSchemes = map[string]bool{
	"ircs": true, "irc": true, "irc+insecure": true, "unix": true, "https": true, "http": true,
	"http+insecure": true, "http+unix": true, "wss": true, "ws": true, "ws+insecure": true,
	"ws+unix": true, "ident": true, "http+prometheus": true, "http+insecure+prometheus": true,
	"http+pprof": true, "unix+admin": true,
}

func checkConfig(text string, cfg Config) ConfigCheck {
	res := ConfigCheck{Errors: []string{}, Warnings: []string{}}
	errf := func(format string, args ...any) { res.Errors = append(res.Errors, fmt.Sprintf(format, args...)) }
	warnf := func(format string, args ...any) { res.Warnings = append(res.Warnings, fmt.Sprintf(format, args...)) }

	block, err := scfg.Read(strings.NewReader(text))
	if err != nil {
		errf("syntax: %v", err)
		return res
	}

	seen := map[string]int{}
	adminSocket := false
	for _, d := range block {
		seen[d.Name]++
		limits, known := sojuDirectives[d.Name]
		if !known {
			errf("unknown directive %q: soju v0.11 refuses to start with it", d.Name)
			continue
		}
		if len(d.Children) > 0 {
			errf("%s: blocks are not supported", d.Name)
		}
		if n := len(d.Params); n < limits[0] || (limits[1] >= 0 && n > limits[1]) {
			errf("%s: wrong number of parameters (%d)", d.Name, n)
			continue
		}
		p := d.Params
		switch d.Name {
		case "listen":
			u, err := url.Parse(p[0])
			if err != nil {
				errf("listen %q: %v", p[0], err)
				break
			}
			scheme := u.Scheme
			if !strings.Contains(p[0], "://") {
				scheme = "ircs"
			}
			if !listenSchemes[scheme] {
				errf("listen %q: unknown scheme %q", p[0], scheme)
			}
			if scheme == "unix+admin" && path.Clean(u.Host+u.Path) == path.Clean(cfg.SocketPath) {
				adminSocket = true
			}
		case "accept-proxy-unix", "enable-user-on-auth", "client-cert-auth":
			if p[0] != "true" && p[0] != "false" {
				errf("%s: must be true or false, got %q", d.Name, p[0])
			}
		case "accept-proxy-ip", "upstream-user-ip":
			for _, cidr := range p {
				if _, _, err := net.ParseCIDR(cidr); err != nil && !(d.Name == "accept-proxy-ip" && cidr == "localhost") {
					errf("%s: %q is not a CIDR like 10.0.0.0/8", d.Name, cidr)
				}
			}
		case "max-user-networks":
			if _, err := strconv.Atoi(p[0]); err != nil {
				errf("max-user-networks: %q is not a number", p[0])
			}
		case "disable-inactive-user", "message-expiry":
			days, ok := strings.CutSuffix(p[0], "d")
			if n, err := strconv.ParseFloat(days, 64); !ok || err != nil || n <= 0 {
				errf("%s: expected a number of days like \"30d\", got %q", d.Name, p[0])
			}
		case "db":
			if p[0] != "sqlite3" && p[0] != "postgres" {
				errf("db: unknown driver %q", p[0])
			} else if p[0] != "sqlite3" || path.Clean(p[1]) != path.Clean(cfg.DBPath) {
				warnf("db no longer points to %s: soju will start with a different database and this panel will keep reading the old one", cfg.DBPath)
			}
		case "message-store", "log":
			switch p[0] {
			case "db", "memory":
			case "fs":
				if len(p) < 2 {
					errf("%s fs: a directory is required", d.Name)
				}
			default:
				errf("%s: unknown driver %q", d.Name, p[0])
			}
			if p[0] != "db" {
				warnf("message-store is not \"db\": message stats and purging in this panel only cover the database store")
			}
		case "file-upload":
			if (p[0] != "fs" && p[0] != "http") || len(p) < 2 {
				errf("file-upload: expected \"fs <dir>\" or \"http <url>\"")
			}
		case "auth":
			switch p[0] {
			case "internal", "pam":
			case "http", "oauth2":
				if len(p) < 2 {
					errf("auth %s: a URL is required", p[0])
				}
			default:
				errf("auth: unknown driver %q", p[0])
			}
			if p[0] != "internal" {
				warnf("auth is not internal: logging into this panel still checks the passwords stored in soju's database")
			}
		}
	}
	for name, n := range seen {
		if n > 1 && !repeatableDirectives[name] {
			if _, known := sojuDirectives[name]; known {
				errf("%s appears %d times; soju only accepts it once", name, n)
			}
		}
	}
	sort.Strings(res.Errors)
	if seen["log"] > 0 && seen["message-store"] > 0 {
		warnf("both log and message-store are set; log is a deprecated alias")
	}
	if !adminSocket {
		errf("the config must keep \"listen unix+admin://%s\": this panel controls soju through that socket", cfg.SocketPath)
	}
	return res
}
