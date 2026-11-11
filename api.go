package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type App struct {
	cfg      Config
	bouncer  *Bouncer
	store    *Store
	kube     *Kube // nil outside Kubernetes
	sessions *Sessions
	jobs     *Jobs
	privs    string
}

type apiHandler func(w http.ResponseWriter, r *http.Request, sess *session) (any, error)

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &httpError{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	body := map[string]any{"error": err.Error()}
	var he *httpError
	var ce *CommandError
	switch {
	case errors.As(err, &he):
		code = he.code
	case errors.As(err, &ce):
		// soju rejected the command: that's the user's input, not our failure.
		code = http.StatusUnprocessableEntity
		body["output"] = ce.Output
	case errors.Is(err, errBusy):
		code = http.StatusConflict
	}
	writeJSON(w, code, body)
}

// wrap enforces a valid session (and CSRF token for anything that writes),
// and logs every mutating call with the admin who made it.
func (a *App) wrap(h apiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := a.sessions.Get(r)
		if sess == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session"})
			return
		}
		if r.Method != http.MethodGet && !checkCSRF(sess, r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
			return
		}
		if r.Method != http.MethodGet {
			log.Printf("audit: %s %s %s", sess.user, r.Method, r.URL.Path)
		}
		v, err := h(w, r, sess)
		if err != nil {
			writeError(w, err)
			return
		}
		if v != nil {
			writeJSON(w, http.StatusOK, v)
		}
	}
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid JSON: %v", err)
	}
	return nil
}

func (a *App) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		a.sessions.Destroy(w, r)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/me", a.wrap(func(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
		return map[string]any{"user": s.user, "csrf": s.csrf, "kube": a.kube != nil, "pod": a.cfg.PodName}, nil
	}))

	mux.HandleFunc("GET /api/overview", a.wrap(a.overview))

	mux.HandleFunc("GET /api/users", a.wrap(a.listUsers))
	mux.HandleFunc("POST /api/users", a.wrap(a.createUser))
	mux.HandleFunc("PATCH /api/users/{user}", a.wrap(a.updateUser))
	mux.HandleFunc("DELETE /api/users/{user}", a.wrap(a.deleteUser))

	mux.HandleFunc("GET /api/users/{user}/networks", a.wrap(a.listNetworks))
	mux.HandleFunc("POST /api/users/{user}/networks", a.wrap(a.createNetwork))
	mux.HandleFunc("PATCH /api/users/{user}/networks/{net}", a.wrap(a.updateNetwork))
	mux.HandleFunc("DELETE /api/users/{user}/networks/{net}", a.wrap(a.deleteNetwork))
	mux.HandleFunc("POST /api/users/{user}/networks/{net}/reconnect", a.wrap(a.reconnectNetwork))
	mux.HandleFunc("PUT /api/users/{user}/networks/{net}/sasl", a.wrap(a.setSASL))
	mux.HandleFunc("DELETE /api/users/{user}/networks/{net}/sasl", a.wrap(a.resetSASL))
	mux.HandleFunc("POST /api/users/{user}/networks/{net}/quote", a.wrap(a.quoteNetwork))

	mux.HandleFunc("GET /api/users/{user}/networks/{net}/channels", a.wrap(a.listChannels))
	mux.HandleFunc("POST /api/users/{user}/networks/{net}/channels", a.wrap(a.createChannel))
	mux.HandleFunc("PATCH /api/users/{user}/networks/{net}/channels/{chan}", a.wrap(a.updateChannel))
	mux.HandleFunc("DELETE /api/users/{user}/networks/{net}/channels/{chan}", a.wrap(a.deleteChannel))

	mux.HandleFunc("POST /api/server/notice", a.wrap(a.serverNotice))
	mux.HandleFunc("POST /api/server/debug", a.wrap(a.serverDebug))
	mux.HandleFunc("POST /api/command", a.wrap(a.rawCommand))

	mux.HandleFunc("POST /api/soju/reload", a.wrap(a.reloadSoju))
	mux.HandleFunc("POST /api/soju/restart", a.wrap(a.restartSoju))
	mux.HandleFunc("GET /api/config", a.wrap(a.getConfig))
	mux.HandleFunc("PUT /api/config", a.wrap(a.putConfig))
	mux.HandleFunc("POST /api/config/check", a.wrap(func(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
		var req struct {
			Content string `json:"content"`
			Motd    string `json:"motd"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return checkConfig(req.Content, normalizeMotd(req.Motd), a.cfg), nil
	}))
	mux.HandleFunc("GET /api/logs", a.wrap(a.logs))

	mux.HandleFunc("GET /api/db/stats", a.wrap(a.dbStats))
	mux.HandleFunc("POST /api/db/purge/preview", a.wrap(a.purgePreview))
	mux.HandleFunc("POST /api/db/purge", a.wrap(a.purge))
	mux.HandleFunc("POST /api/db/vacuum", a.wrap(a.vacuum))
	mux.HandleFunc("POST /api/db/check", a.wrap(a.integrityCheck))
	mux.HandleFunc("GET /api/backups", a.wrap(func(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
		return a.store.Backups()
	}))
	mux.HandleFunc("POST /api/backups", a.wrap(a.createBackup))
	mux.HandleFunc("GET /api/backups/{name}", a.wrap(a.downloadBackup))
	mux.HandleFunc("DELETE /api/backups/{name}", a.wrap(a.deleteBackup))

	mux.HandleFunc("GET /api/jobs", a.wrap(func(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
		return a.jobs.List(), nil
	}))
	mux.HandleFunc("GET /api/jobs/{id}", a.wrap(func(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		j, ok := a.jobs.Get(id)
		if !ok {
			return nil, &httpError{http.StatusNotFound, "no such operation"}
		}
		return j, nil
	}))
}

// --- auth -------------------------------------------------------------------

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.sessions.Throttled(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, wait a few minutes"})
		return
	}
	var req struct{ Username, Password string }
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := a.store.CheckAdmin(r.Context(), req.Username, req.Password); err != nil {
		a.sessions.Fail(ip)
		log.Printf("audit: failed login for %q from %s: %v", req.Username, ip, err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	a.sessions.Succeed(ip)
	sess := a.sessions.Create(w, req.Username)
	log.Printf("audit: login by %q from %s", req.Username, ip)
	writeJSON(w, http.StatusOK, map[string]any{"user": sess.user, "csrf": sess.csrf})
}

// --- overview ---------------------------------------------------------------

func (a *App) overview(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	ctx := r.Context()
	out := map[string]any{"privileges": a.privs, "version": version}

	if lines, err := a.bouncer.Run(ctx, "server", "status"); err != nil {
		out["socket_error"] = err.Error()
	} else {
		out["server_status"] = strings.Join(lines, "\n")
	}
	if p, err := sojuProcInfo(); err != nil {
		out["process_error"] = err.Error()
	} else {
		out["process"] = p
	}
	if a.kube != nil && a.cfg.PodName != "" {
		if pod, err := a.kube.Pod(ctx, a.cfg.PodName); err != nil {
			out["pod_error"] = err.Error()
		} else {
			out["pod"] = pod
		}
	}
	var dbSize int64
	for _, suffix := range []string{"", "-wal"} {
		if fi, err := os.Stat(a.store.Path + suffix); err == nil {
			dbSize += fi.Size()
		}
	}
	out["db_size"] = dbSize
	out["volume_free"], out["volume_total"] = diskUsage(a.cfg.DataDir)
	return out, nil
}

// --- users ------------------------------------------------------------------

func (a *App) listUsers(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	users, err := a.store.Users(r.Context())
	if err != nil {
		return nil, err
	}
	// Users that soju has loaded in memory show up in "user status".
	loaded := map[string]bool{}
	lines, statusErr := a.bouncer.Run(r.Context(), "user", "status")
	for _, l := range lines {
		name, _, _ := strings.Cut(l, " ")
		name, _, _ = strings.Cut(name, ":")
		loaded[name] = true
	}
	ids := make([]int64, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	upstream, upstreamErr := upstreamIPsByUser(a.cfg.SojuConfig, ids)

	type userOut struct {
		User
		Loaded bool `json:"loaded"`
		// nil when upstream-user-ip isn't set: soju uses the host's default address.
		UpstreamIPs []UpstreamIP `json:"upstream_ips"`
	}
	out := make([]userOut, 0, len(users))
	for _, u := range users {
		out = append(out, userOut{u, loaded[u.Username], upstream[u.ID]})
	}
	res := map[string]any{"users": out}
	if statusErr != nil {
		res["status_error"] = statusErr.Error()
	}
	if upstreamErr != nil {
		res["upstream_error"] = upstreamErr.Error()
	}
	return res, nil
}

type userReq struct {
	Username    *string `json:"username"`
	Password    *string `json:"password"`
	Admin       *bool   `json:"admin"`
	Enabled     *bool   `json:"enabled"`
	Nick        *string `json:"nick"`
	Realname    *string `json:"realname"`
	MaxNetworks *int    `json:"max_networks"`
}

func (u userReq) flags() []string {
	var f []string
	if u.Password != nil && *u.Password != "" {
		f = append(f, "-password="+*u.Password)
	}
	if u.Admin != nil {
		f = append(f, "-admin="+strconv.FormatBool(*u.Admin))
	}
	if u.Enabled != nil {
		f = append(f, "-enabled="+strconv.FormatBool(*u.Enabled))
	}
	if u.Nick != nil {
		f = append(f, "-nick="+*u.Nick)
	}
	if u.Realname != nil {
		f = append(f, "-realname="+*u.Realname)
	}
	if u.MaxNetworks != nil {
		f = append(f, "-max-networks="+strconv.Itoa(*u.MaxNetworks))
	}
	return f
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var req userReq
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Username == nil || strings.TrimSpace(*req.Username) == "" {
		return nil, badRequest("username is required")
	}
	if req.Password == nil || *req.Password == "" {
		return nil, badRequest("password is required")
	}
	args := append([]string{"user", "create", "-username=" + *req.Username}, req.flags()...)
	return cmdResult(a.bouncer.Run(r.Context(), args...))
}

func (a *App) updateUser(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var req userReq
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	user := r.PathValue("user")
	if user == s.user && ((req.Admin != nil && !*req.Admin) || (req.Enabled != nil && !*req.Enabled)) {
		return nil, badRequest("you cannot remove your own admin flag or disable yourself from the panel")
	}
	// soju refuses -nick/-realname on other users, so those are applied
	// from inside the user's own context ("user run <u> user update").
	self := userReq{Nick: req.Nick, Realname: req.Realname}
	req.Nick, req.Realname = nil, nil
	var out []string
	if flags := self.flags(); len(flags) > 0 {
		lines, err := a.bouncer.RunAs(r.Context(), user, append([]string{"user", "update"}, flags...)...)
		out = append(out, lines...)
		if err != nil {
			return nil, err
		}
	}
	if flags := req.flags(); len(flags) > 0 {
		lines, err := a.bouncer.Run(r.Context(), append([]string{"user", "update", user}, flags...)...)
		out = append(out, lines...)
		if err != nil {
			return nil, err
		}
	}
	if out == nil {
		return nil, badRequest("nothing to change")
	}
	return cmdResult(out, nil)
}

func (a *App) deleteUser(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user := r.PathValue("user")
	if user == s.user {
		return nil, badRequest("you cannot delete your own user from the panel")
	}
	return cmdResult(a.bouncer.DeleteUser(r.Context(), user))
}

func cmdResult(lines []string, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	if lines == nil {
		lines = []string{}
	}
	return map[string]any{"output": lines}, nil
}

// --- networks ---------------------------------------------------------------

type networkStatus struct {
	Network
	State   string `json:"state"`
	Details string `json:"details"`
}

// parseNetworkStatus matches soju's "name (addr) [status, ...]: details" lines.
func parseNetworkStatus(n Network, lines []string) (state, details string) {
	for _, l := range lines {
		if !strings.HasPrefix(l, n.DisplayName+" [") && !strings.HasPrefix(l, n.DisplayName+" ("+n.Addr+") [") {
			continue
		}
		open := strings.Index(l, " [")
		if n.DisplayName != n.Addr {
			open = strings.Index(l, ") [") + 1
		}
		rest := l[open+2:]
		end := strings.Index(rest, "]")
		if end < 0 {
			return "unknown", l
		}
		state = rest[:end]
		if d, ok := strings.CutPrefix(rest[end+1:], ": "); ok {
			details = d
		}
		return state, details
	}
	return "unknown", ""
}

func (a *App) listNetworks(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user := r.PathValue("user")
	nets, err := a.store.Networks(r.Context(), user)
	if err != nil {
		return nil, err
	}
	res := map[string]any{}
	var lines []string
	if len(nets) > 0 {
		lines, err = a.bouncer.RunAs(r.Context(), user, "network", "status")
		if err != nil {
			res["status_error"] = err.Error()
		}
	}
	out := make([]networkStatus, 0, len(nets))
	for _, n := range nets {
		st, det := parseNetworkStatus(n, lines)
		if err != nil {
			st = "unknown"
		}
		out = append(out, networkStatus{n, st, det})
	}
	res["networks"] = out
	return res, nil
}

// network resolves the {net} path value (a DB id) to the name soju expects.
func (a *App) network(r *http.Request) (string, *Network, error) {
	user := r.PathValue("user")
	id, err := strconv.ParseInt(r.PathValue("net"), 10, 64)
	if err != nil {
		return "", nil, badRequest("invalid network id")
	}
	nets, err := a.store.Networks(r.Context(), user)
	if err != nil {
		return "", nil, err
	}
	for i := range nets {
		if nets[i].ID == id {
			return user, &nets[i], nil
		}
	}
	return "", nil, &httpError{http.StatusNotFound, "network not found"}
}

type networkReq struct {
	Addr            *string   `json:"addr"`
	Name            *string   `json:"name"`
	Nick            *string   `json:"nick"`
	Username        *string   `json:"username"`
	Realname        *string   `json:"realname"`
	Pass            *string   `json:"pass"`
	CertFP          *string   `json:"certfp"`
	Enabled         *bool     `json:"enabled"`
	AutoAway        *bool     `json:"auto_away"`
	ConnectCommands *[]string `json:"connect_commands"`
	IgnoreLimit     bool      `json:"ignore_limit"`
}

func (n networkReq) flags() []string {
	var f []string
	str := func(name string, v *string) {
		if v != nil {
			f = append(f, "-"+name+"="+*v)
		}
	}
	str("addr", n.Addr)
	str("name", n.Name)
	str("nick", n.Nick)
	str("username", n.Username)
	str("realname", n.Realname)
	str("pass", n.Pass)
	str("certfp", n.CertFP)
	if n.Enabled != nil {
		f = append(f, "-enabled="+strconv.FormatBool(*n.Enabled))
	}
	if n.AutoAway != nil {
		f = append(f, "-auto-away="+strconv.FormatBool(*n.AutoAway))
	}
	if n.ConnectCommands != nil {
		for _, c := range *n.ConnectCommands {
			if c = strings.TrimSpace(c); c != "" {
				f = append(f, "-connect-command="+c)
			}
		}
	}
	if n.IgnoreLimit {
		f = append(f, "-ignore-limit")
	}
	return f
}

func (a *App) createNetwork(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var req networkReq
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Addr == nil || *req.Addr == "" {
		return nil, badRequest("address is required (e.g. ircs://irc.libera.chat)")
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), r.PathValue("user"), append([]string{"network", "create"}, req.flags()...)...))
}

func (a *App) updateNetwork(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	var req networkReq
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	flags := req.flags()
	if len(flags) == 0 {
		return nil, badRequest("nothing to change")
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), user, append([]string{"network", "update", n.DisplayName}, flags...)...))
}

func (a *App) deleteNetwork(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), user, "network", "delete", n.DisplayName))
}

func (a *App) reconnectNetwork(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	out1, err := a.bouncer.RunAs(r.Context(), user, "network", "update", n.DisplayName, "-enabled=false")
	if err != nil {
		return nil, err
	}
	time.Sleep(time.Second)
	out2, err := a.bouncer.RunAs(r.Context(), user, "network", "update", n.DisplayName, "-enabled=true")
	return cmdResult(append(out1, out2...), err)
}

func (a *App) setSASL(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	var req struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		Reconnect bool   `json:"reconnect"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Username == "" || req.Password == "" {
		return nil, badRequest("SASL username and password are required")
	}
	out, err := a.bouncer.RunAs(r.Context(), user, "sasl", "set-plain", "-network="+n.DisplayName, req.Username, req.Password)
	if err != nil || !req.Reconnect {
		return cmdResult(out, err)
	}
	// soju only uses new SASL credentials on the next connection.
	if more, err := a.bouncer.RunAs(r.Context(), user, "network", "update", n.DisplayName, "-enabled=false"); err == nil {
		out = append(out, more...)
		time.Sleep(time.Second)
		more, err = a.bouncer.RunAs(r.Context(), user, "network", "update", n.DisplayName, "-enabled=true")
		out = append(out, more...)
		return cmdResult(out, err)
	} else {
		return nil, err
	}
}

func (a *App) resetSASL(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), user, "sasl", "reset", "-network="+n.DisplayName))
}

func (a *App) quoteNetwork(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	var req struct {
		Line string `json:"line"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Line) == "" {
		return nil, badRequest("empty line")
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), user, "network", "quote", n.DisplayName, req.Line))
}

// --- channels ---------------------------------------------------------------

func (a *App) listChannels(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	_, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	return a.store.Channels(r.Context(), n.ID)
}

type channelReq struct {
	Name          string  `json:"name"`
	Detached      *bool   `json:"detached"`
	RelayDetached *string `json:"relay_detached"`
	ReattachOn    *string `json:"reattach_on"`
	DetachAfter   *int64  `json:"detach_after"`
	DetachOn      *string `json:"detach_on"`
}

func (c channelReq) flags() []string {
	var f []string
	if c.Detached != nil {
		f = append(f, "-detached="+strconv.FormatBool(*c.Detached))
	}
	for _, p := range []struct {
		name string
		v    *string
	}{{"relay-detached", c.RelayDetached}, {"reattach-on", c.ReattachOn}, {"detach-on", c.DetachOn}} {
		if p.v != nil {
			f = append(f, "-"+p.name+"="+*p.v)
		}
	}
	if c.DetachAfter != nil {
		f = append(f, fmt.Sprintf("-detach-after=%ds", *c.DetachAfter))
	}
	return f
}

func (a *App) createChannel(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	var req channelReq
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, badRequest("channel name is required")
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), user, append([]string{"channel", "create", req.Name + "/" + n.DisplayName}, req.flags()...)...))
}

func (a *App) updateChannel(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	var req channelReq
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	flags := req.flags()
	if len(flags) == 0 {
		return nil, badRequest("nothing to change")
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), user, append([]string{"channel", "update", r.PathValue("chan") + "/" + n.DisplayName}, flags...)...))
}

func (a *App) deleteChannel(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	user, n, err := a.network(r)
	if err != nil {
		return nil, err
	}
	return cmdResult(a.bouncer.RunAs(r.Context(), user, "channel", "delete", r.PathValue("chan")+"/"+n.DisplayName))
}

// --- server -----------------------------------------------------------------

func (a *App) serverNotice(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var req struct {
		Text string `json:"text"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Text) == "" {
		return nil, badRequest("empty message")
	}
	return cmdResult(a.bouncer.Run(r.Context(), "server", "notice", req.Text))
}

func (a *App) serverDebug(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	return cmdResult(a.bouncer.Run(r.Context(), "server", "debug", strconv.FormatBool(req.Enabled)))
}

func (a *App) rawCommand(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var req struct {
		As      string `json:"as"`
		Command string `json:"command"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	words, err := splitWords(req.Command)
	if err != nil {
		return nil, badRequest("%v", err)
	}
	if len(words) == 0 {
		return nil, badRequest("empty command")
	}
	if req.As != "" {
		return cmdResult(a.bouncer.RunAs(r.Context(), req.As, words...))
	}
	return cmdResult(a.bouncer.Run(r.Context(), words...))
}

// splitWords mirrors BouncerServ's parsing: whitespace-separated words,
// double quotes group, backslash escapes the next character.
func splitWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, quoted, escaped := false, false, false
	for _, ch := range s {
		switch {
		case escaped:
			cur.WriteRune(ch)
			escaped = false
		case ch == '\\':
			escaped, inWord = true, true
		case ch == '"':
			quoted, inWord = !quoted, true
		case !quoted && (ch == ' ' || ch == '\t'):
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(ch)
			inWord = true
		}
	}
	if quoted {
		return nil, errors.New("unterminated quote")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// --- process & config -------------------------------------------------------

func (a *App) reloadSoju(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	pid, err := signalSoju(syscall.SIGHUP)
	if err != nil {
		return nil, err
	}
	return map[string]any{"output": []string{fmt.Sprintf("sent SIGHUP to soju (pid %d): configuration reloaded", pid)}}, nil
}

func (a *App) restartSoju(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	return a.jobs.Start("restart soju", s.user, 3*time.Minute, func(ctx context.Context, j *Job) error {
		return restartSoju(ctx, a.bouncer, j.Logf)
	})
}

func (a *App) getConfig(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	live, err := os.ReadFile(a.cfg.SojuConfig)
	if err != nil {
		return nil, err
	}
	liveMotd, _ := os.ReadFile(a.cfg.MotdPath)
	out := map[string]any{
		"live": string(live), "path": a.cfg.SojuConfig, "editable": false, "admin_socket": a.cfg.SocketPath,
		"motd_path": a.cfg.MotdPath, "motd": string(liveMotd),
	}
	if a.kube != nil && a.cfg.ConfigMap != "" {
		data, err := a.kube.ConfigMapData(r.Context(), a.cfg.ConfigMap)
		if err == nil && data[a.cfg.ConfigMapKey] == "" {
			err = fmt.Errorf("ConfigMap %s has no key %q", a.cfg.ConfigMap, a.cfg.ConfigMapKey)
		}
		if err != nil {
			out["configmap_error"] = err.Error()
		} else {
			out["configmap"] = data[a.cfg.ConfigMapKey]
			out["motd"] = data[a.cfg.MotdKey]
			out["editable"] = true
			out["configmap_name"] = a.cfg.ConfigMap
		}
	}
	return out, nil
}

// normalizeMotd keeps a single trailing newline, so the text compares equal
// to the file the kubelet writes from the ConfigMap.
func normalizeMotd(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimRight(s, "\n\t ")
	if s == "" {
		return ""
	}
	return s + "\n"
}

func (a *App) putConfig(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	if a.kube == nil || a.cfg.ConfigMap == "" {
		return nil, badRequest("editing the config requires ConfigMap access (SOJU_CONFIGMAP)")
	}
	var req struct {
		Content string  `json:"content"`
		Motd    *string `json:"motd"`  // nil = leave the MOTD key untouched
		Apply   string  `json:"apply"` // none, reload, restart
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Content) == "" {
		return nil, badRequest("the configuration cannot be empty")
	}
	if !strings.HasSuffix(req.Content, "\n") {
		req.Content += "\n"
	}
	current, err := a.kube.ConfigMapData(r.Context(), a.cfg.ConfigMap)
	if err != nil {
		return nil, err
	}
	motd := current[a.cfg.MotdKey]
	if req.Motd != nil {
		motd = normalizeMotd(*req.Motd)
	}
	if check := checkConfig(req.Content, motd, a.cfg); len(check.Errors) > 0 {
		return nil, &httpError{http.StatusUnprocessableEntity, "invalid configuration:\n" + strings.Join(check.Errors, "\n")}
	}

	patch := map[string]*string{a.cfg.ConfigMapKey: &req.Content}
	if req.Motd != nil && motd != current[a.cfg.MotdKey] {
		if motd == "" {
			patch[a.cfg.MotdKey] = nil // JSON null removes the key
		} else {
			patch[a.cfg.MotdKey] = &motd
		}
	}

	return a.jobs.Start("apply configuration", s.user, 5*time.Minute, func(ctx context.Context, j *Job) error {
		stamp := time.Now().UTC().Format("20060102-150405")
		os.MkdirAll(a.store.BackupDir, 0o700)
		if old, err := os.ReadFile(a.cfg.SojuConfig); err == nil {
			backup := fmt.Sprintf("%s/config-%s.bak", a.store.BackupDir, stamp)
			if err := os.WriteFile(backup, old, 0o600); err == nil {
				j.Logf("previous config saved to %s", backup)
			}
		}
		if old, err := os.ReadFile(a.cfg.MotdPath); err == nil && len(patch) > 1 {
			backup := fmt.Sprintf("%s/motd-%s.bak", a.store.BackupDir, stamp)
			if err := os.WriteFile(backup, old, 0o600); err == nil {
				j.Logf("previous message of the day saved to %s", backup)
			}
		}
		if err := a.kube.PatchConfigMap(ctx, a.cfg.ConfigMap, patch); err != nil {
			return err
		}
		if _, ok := patch[a.cfg.MotdKey]; ok {
			j.Logf("ConfigMap %s updated (config and message of the day)", a.cfg.ConfigMap)
		} else {
			j.Logf("ConfigMap %s updated", a.cfg.ConfigMap)
		}
		if req.Apply == "none" || req.Apply == "" {
			j.Logf("not applied: the kubelet will sync the files in ~1 min; reload or restart whenever you want")
			return nil
		}
		j.Logf("waiting for the kubelet to update %s (can take up to ~2 min)…", path.Dir(a.cfg.SojuConfig))
		for !a.filesSynced(req.Content, motd) {
			select {
			case <-ctx.Done():
				return fmt.Errorf("the mounted files were not updated in time")
			case <-time.After(2 * time.Second):
			}
		}
		j.Logf("files updated inside the container")
		if req.Apply == "restart" {
			return restartSoju(ctx, a.bouncer, j.Logf)
		}
		pid, err := signalSoju(syscall.SIGHUP)
		if err != nil {
			return err
		}
		j.Logf("sent SIGHUP to soju (pid %d); check the logs for reload errors", pid)
		return nil
	})
}

// filesSynced reports whether the mounted ConfigMap already reflects the
// new config and MOTD (a removed MOTD key means the file is gone).
func (a *App) filesSynced(config, motd string) bool {
	cur, err := os.ReadFile(a.cfg.SojuConfig)
	if err != nil || string(cur) != config {
		return false
	}
	curMotd, err := os.ReadFile(a.cfg.MotdPath)
	if motd == "" {
		return errors.Is(err, os.ErrNotExist)
	}
	return err == nil && string(curMotd) == motd
}

func (a *App) logs(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	if a.kube == nil || a.cfg.PodName == "" {
		return nil, badRequest("logs require Kubernetes API access (POD_NAME)")
	}
	tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	if tail <= 0 || tail > 5000 {
		tail = 500
	}
	container := r.URL.Query().Get("container")
	if container == "" {
		container = a.cfg.SojuContainer
	}
	text, err := a.kube.PodLogs(r.Context(), a.cfg.PodName, container, tail, r.URL.Query().Get("previous") == "1")
	if err != nil {
		return nil, err
	}
	return map[string]any{"logs": text}, nil
}

// --- database ---------------------------------------------------------------

func (a *App) dbStats(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	return a.store.Stats(r.Context())
}

func (a *App) purgePreview(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var f PurgeFilter
	if err := decode(r, &f); err != nil {
		return nil, err
	}
	n, err := a.store.PurgeCount(r.Context(), f)
	if err != nil {
		return nil, err
	}
	return map[string]int64{"messages": n}, nil
}

func (a *App) purge(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	var req struct {
		PurgeFilter
		Backup bool `json:"backup"`
		Vacuum bool `json:"vacuum"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	f := req.PurgeFilter
	return a.jobs.Start("purge messages", s.user, 2*time.Hour, func(ctx context.Context, j *Job) error {
		n, err := a.store.PurgeCount(ctx, f)
		if err != nil {
			return err
		}
		j.Logf("%d messages match the filter", n)
		if n == 0 {
			return nil
		}
		if req.Backup {
			j.Logf("creating backup first…")
			b, err := a.store.Backup(ctx, "prepurge")
			if err != nil {
				return err
			}
			j.Logf("backup %s (%s)", b.Name, humanBytes(b.Size))
			a.store.PruneBackups(a.cfg.KeepBackups)
		}
		last := time.Now()
		deleted, err := a.store.Purge(ctx, f, func(d int64) {
			if time.Since(last) > 2*time.Second {
				j.Logf("deleted %d / %d", d, n)
				last = time.Now()
			}
		})
		j.Logf("deleted %d messages", deleted)
		if err != nil {
			return err
		}
		if req.Vacuum {
			j.Logf("compacting database (VACUUM)…")
			if err := a.store.Vacuum(ctx); err != nil {
				return err
			}
			if fi, err := os.Stat(a.store.Path); err == nil {
				j.Logf("soju.db size after VACUUM: %s", humanBytes(fi.Size()))
			}
		}
		return nil
	})
}

func (a *App) vacuum(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	return a.jobs.Start("VACUUM", s.user, time.Hour, func(ctx context.Context, j *Job) error {
		if fi, err := os.Stat(a.store.Path); err == nil {
			j.Logf("size before: %s", humanBytes(fi.Size()))
		}
		if err := a.store.Vacuum(ctx); err != nil {
			return err
		}
		if fi, err := os.Stat(a.store.Path); err == nil {
			j.Logf("size after: %s", humanBytes(fi.Size()))
		}
		return nil
	})
}

func (a *App) integrityCheck(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	return a.jobs.Start("integrity check", s.user, time.Hour, func(ctx context.Context, j *Job) error {
		lines, err := a.store.IntegrityCheck(ctx)
		if err != nil {
			return err
		}
		for _, l := range lines {
			j.Logf("%s", l)
		}
		if len(lines) != 1 || lines[0] != "ok" {
			return errors.New("the database has integrity problems")
		}
		return nil
	})
}

func (a *App) createBackup(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	return a.jobs.Start("backup", s.user, time.Hour, func(ctx context.Context, j *Job) error {
		b, err := a.store.Backup(ctx, "manual")
		if err != nil {
			return err
		}
		j.Logf("backup %s (%s)", b.Name, humanBytes(b.Size))
		a.store.PruneBackups(a.cfg.KeepBackups)
		return nil
	})
}

func (a *App) downloadBackup(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	p, err := a.store.BackupPath(r.PathValue("name"))
	if err != nil {
		return nil, &httpError{http.StatusNotFound, err.Error()}
	}
	log.Printf("audit: %s downloads backup %s", s.user, r.PathValue("name"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", r.PathValue("name")))
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	http.ServeFile(w, r, p)
	return nil, nil
}

func (a *App) deleteBackup(w http.ResponseWriter, r *http.Request, s *session) (any, error) {
	p, err := a.store.BackupPath(r.PathValue("name"))
	if err != nil {
		return nil, &httpError{http.StatusNotFound, err.Error()}
	}
	if err := os.Remove(p); err != nil {
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
