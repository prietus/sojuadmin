package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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
	cfg := Config{SocketPath: "/data/admin.sock", DBPath: "/data/soju.db"}
	good := "# comment\nlisten irc+insecure://0.0.0.0:6667\nlisten unix+admin:///data/admin.sock\nhostname irc.example.org\n" +
		"db sqlite3 /data/soju.db\nmessage-store db\nhttp-ingress https://web.example.org\nmessage-expiry 90d\n" +
		"file-upload http http://uploader:8081/upload\naccept-proxy-ip localhost 10.0.0.0/8\n"
	if res := checkConfig(good, cfg); len(res.Errors) != 0 || len(res.Warnings) != 0 {
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
		if res := checkConfig(text, cfg); len(res.Errors) == 0 {
			t.Errorf("%s: expected errors, got %+v", name, res)
		}
	}
}
