package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSplitWords(t *testing.T) {
	for in, want := range map[string][]string{
		`network status`:                    {"network", "status"},
		`sasl set-plain -network x "a b" c`: {"sasl", "set-plain", "-network", "x", "a b", "c"},
		`quote "PRIVMSG x :hi \"there\""`:   {"quote", `PRIVMSG x :hi "there"`},
		`  a\ b  `:                          {"a b"},
	} {
		got, err := splitWords(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("splitWords(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := splitWords(`"open`); err == nil {
		t.Error("expected error for unterminated quote")
	}
}

func TestParseNetworkStatus(t *testing.T) {
	lines := []string{
		`libera (ircs://irc.libera.chat) [connected]: 12 channels`,
		`ircs://testnet.ergo.chat [disconnected]: connection error: timeout`,
		`off (ircs://x) [disabled]`,
	}
	cases := []struct {
		n             Network
		state, detail string
	}{
		{Network{DisplayName: "libera", Addr: "ircs://irc.libera.chat"}, "connected", "12 channels"},
		{Network{DisplayName: "ircs://testnet.ergo.chat", Addr: "ircs://testnet.ergo.chat"}, "disconnected", "connection error: timeout"},
		{Network{DisplayName: "off", Addr: "ircs://x"}, "disabled", ""},
		{Network{DisplayName: "missing", Addr: "ircs://y"}, "unknown", ""},
	}
	for _, c := range cases {
		st, det := parseNetworkStatus(c.n, lines)
		if st != c.state || det != c.detail {
			t.Errorf("%s: got %q/%q, want %q/%q", c.n.DisplayName, st, det, c.state, c.detail)
		}
	}
}

func TestPurge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "soju.db")
	schema, err := os.ReadFile("testdata/soju_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path, filepath.Join(dir, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.db.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`INSERT INTO User(username, created_at) VALUES ('u', '2020-01-01T00:00:00.000Z')`)
	s.db.Exec(`INSERT INTO Network(user, addr) VALUES (1, 'ircs://a'), (1, 'ircs://b')`)
	s.db.Exec(`INSERT INTO MessageTarget(network, target) VALUES (1, '#a'), (2, '#b')`)
	now := time.Now().UTC()
	for i := 0; i < 5000; i++ {
		ts := now.AddDate(0, 0, -(i % 100)).Format(sqliteTimeLayout)
		if _, err := s.db.Exec(`INSERT INTO Message(target, raw, time, sender, text) VALUES (?, 'raw', ?, 'x', 'hi')`, 1+i%2, ts); err != nil {
			t.Fatal(err)
		}
	}

	f := PurgeFilter{NetworkID: 1, OlderThanDays: 50}
	want, err := s.PurgeCount(ctx, f)
	if err != nil || want == 0 {
		t.Fatalf("PurgeCount = %d, %v", want, err)
	}
	if _, err := s.Backup(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Purge(ctx, f, nil)
	if err != nil || got != want {
		t.Fatalf("Purge = %d, %v; want %d", got, err, want)
	}
	if n, _ := s.PurgeCount(ctx, PurgeFilter{NetworkID: 2}); n != 2500 {
		t.Errorf("network 2 should be untouched, has %d", n)
	}
	if err := s.Vacuum(ctx); err != nil {
		t.Fatal(err)
	}
	if lines, err := s.IntegrityCheck(ctx); err != nil || lines[0] != "ok" {
		t.Errorf("integrity: %v %v", lines, err)
	}
	if bs, _ := s.Backups(); len(bs) != 1 {
		t.Errorf("expected 1 backup, got %d", len(bs))
	}
	if _, err := s.BackupPath("../soju.db"); err == nil {
		t.Error("BackupPath accepted a traversal")
	}
}

func TestCheckConfig(t *testing.T) {
	cfg := Config{SocketPath: "/data/admin.sock", DBPath: "/data/soju.db", MotdPath: "/etc/soju/motd"}
	good := "# comment\nlisten irc+insecure://0.0.0.0:6667\nlisten unix+admin:///data/admin.sock\nhostname irc.example.org\n" +
		"db sqlite3 /data/soju.db\nmessage-store db\nhttp-ingress https://web.example.org\nmessage-expiry 90d\n" +
		"file-upload http http://uploader:8081/upload\naccept-proxy-ip localhost 10.0.0.0/8\n"
	if res := checkConfig(good, "", cfg); len(res.Errors) != 0 || len(res.Warnings) != 0 {
		t.Errorf("good config: %+v", res)
	}
	for name, text := range map[string]string{
		"no admin socket": "listen ircs://\n",
		"unknown":         "listen unix+admin:///data/admin.sock\nfoo bar\n",
		"duplicate":       "listen unix+admin:///data/admin.sock\nhostname a\nhostname b\n",
		"bad days":        "listen unix+admin:///data/admin.sock\nmessage-expiry 30\n",
		"bad bool":        "listen unix+admin:///data/admin.sock\nclient-cert-auth yes\n",
		"bad cidr":        "listen unix+admin:///data/admin.sock\naccept-proxy-ip 10.0.0.1\n",
		"bad scheme":      "listen unix+admin:///data/admin.sock\nlisten gopher://x\n",
		"syntax":          "listen unix+admin:///data/admin.sock\ntitle \"unterminated\n",
		"tls one param":   "listen unix+admin:///data/admin.sock\ntls cert.pem\n",
	} {
		if res := checkConfig(text, "", cfg); len(res.Errors) == 0 {
			t.Errorf("%s: expected errors, got %+v", name, res)
		}
	}
}

func TestCheckConfigMotd(t *testing.T) {
	cfg := Config{SocketPath: "/data/admin.sock", DBPath: "/data/soju.db", MotdPath: "/etc/soju/motd"}
	base := "listen unix+admin:///data/admin.sock\n"
	withMotd := base + "motd /etc/soju/motd\n"

	if res := checkConfig(withMotd, "Welcome!\n", cfg); len(res.Errors)+len(res.Warnings) != 0 {
		t.Errorf("managed motd: %+v", res)
	}
	if res := checkConfig(withMotd, "", cfg); len(res.Errors) == 0 {
		t.Error("motd pointing to an empty managed file should be an error")
	}
	if res := checkConfig(base, "Welcome!\n", cfg); len(res.Warnings) == 0 {
		t.Error("unused motd text should warn")
	}
	if res := checkConfig(base+"motd /data/does-not-exist\n", "", cfg); len(res.Errors) == 0 {
		t.Error("missing motd file under /data should be an error")
	}
	if res := checkConfig(base+"motd /srv/motd\n", "", cfg); len(res.Errors) != 0 || len(res.Warnings) == 0 {
		t.Errorf("unverifiable motd path should only warn: %+v", res)
	}
	if res := checkConfig(withMotd, strings.Repeat("x", maxConfigMapBytes), cfg); len(res.Errors) == 0 {
		t.Error("oversized motd should be an error")
	}
}

func TestNormalizeMotd(t *testing.T) {
	for in, want := range map[string]string{"": "", " \n\n": "", "hi": "hi\n", "a\r\nb\n\n\n": "a\nb\n"} {
		if got := normalizeMotd(in); got != want {
			t.Errorf("normalizeMotd(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPatchConfigMap(t *testing.T) {
	var gotType string
	var gotBody map[string]map[string]*string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" || r.URL.Path != "/api/v1/namespaces/soju/configmaps/soju-config" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotType = r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	token := filepath.Join(t.TempDir(), "token")
	os.WriteFile(token, []byte("t"), 0o600)
	k := &Kube{base: srv.URL, namespace: "soju", client: srv.Client(), tokenPath: token}

	config := "listen ircs://\n"
	if err := k.PatchConfigMap(context.Background(), "soju-config", map[string]*string{"config": &config, "motd": nil}); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/merge-patch+json" {
		t.Errorf("content type %q", gotType)
	}
	data := gotBody["data"]
	if v, ok := data["motd"]; !ok || v != nil {
		t.Errorf("motd should be sent as JSON null to delete the key, got %v (present %v)", v, ok)
	}
	if data["config"] == nil || *data["config"] != config {
		t.Errorf("config not sent: %v", data["config"])
	}
}

func TestFilesSynced(t *testing.T) {
	dir := t.TempDir()
	a := &App{cfg: Config{SojuConfig: filepath.Join(dir, "config"), MotdPath: filepath.Join(dir, "motd")}}
	os.WriteFile(a.cfg.SojuConfig, []byte("new\n"), 0o644)
	if a.filesSynced("new\n", "hi\n") {
		t.Error("motd file missing: not synced yet")
	}
	os.WriteFile(a.cfg.MotdPath, []byte("hi\n"), 0o644)
	if !a.filesSynced("new\n", "hi\n") {
		t.Error("both files match: should be synced")
	}
	if a.filesSynced("new\n", "") {
		t.Error("motd removed but file still present: not synced yet")
	}
	os.Remove(a.cfg.MotdPath)
	if !a.filesSynced("new\n", "") {
		t.Error("motd removed and file gone: should be synced")
	}
}

func TestUserUpstreamIP(t *testing.T) {
	for _, c := range []struct {
		cidr string
		id   int64
		want string
	}{
		{"2001:db8:0:1:50:7a::/96", 1, "2001:db8:0:1:50:7a:0:2"},
		{"2001:db8:0:1:50:7a::/96", 2, "2001:db8:0:1:50:7a:0:3"},
		{"2001:db8:0:1:50:7a::/96", 65535, "2001:db8:0:1:50:7a:1:0"},
		{"192.0.2.0/24", 1, "192.0.2.2"},
	} {
		_, n, _ := net.ParseCIDR(c.cidr)
		ip, err := userUpstreamIP(n, c.id)
		if err != nil || ip.String() != c.want {
			t.Errorf("%s id %d = %v, %v; want %s", c.cidr, c.id, ip, err, c.want)
		}
	}
	_, small, _ := net.ParseCIDR("192.0.2.0/30")
	if _, err := userUpstreamIP(small, 5); err == nil {
		t.Error("expected range too small error")
	}
}

func TestParseProcNetTCP(t *testing.T) {
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue
   0: B80D0120010000007A00500002000000:8A4F 00000000000000000000000001000000:1A2B 01 00000000:00000000
   1: B80D0120010000007A00500003000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000
`
	tcp4 := `  sl  local_address rem_address   st
   0: 0100007F:1F90 0100007F:D3A2 01 00000000:00000000
`
	got := map[string]bool{}
	parseProcNetTCP(bufio.NewScanner(strings.NewReader(tcp6)), got)
	parseProcNetTCP(bufio.NewScanner(strings.NewReader(tcp4)), got)
	want := map[string]bool{"2001:db8:0:1:50:7a:0:2": true, "127.0.0.1": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (listening sockets must be ignored)", got, want)
	}
}

func TestUpstreamRanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	os.WriteFile(path, []byte("listen ircs://\nupstream-user-ip 192.0.2.0/24 2001:db8::/64\n"), 0o644)
	ranges, err := upstreamRanges(path)
	if err != nil || len(ranges) != 2 || ranges[1].String() != "2001:db8::/64" {
		t.Errorf("got %v, %v", ranges, err)
	}
	os.WriteFile(path, []byte("listen ircs://\n"), 0o644)
	if ranges, err := upstreamRanges(path); err != nil || len(ranges) != 0 {
		t.Errorf("no directive: got %v, %v", ranges, err)
	}
}
