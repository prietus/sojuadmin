package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Store reads soju's SQLite database directly. Everything that changes
// soju's state (users, networks, channels, SASL) goes through the admin
// socket instead, because soju keeps that state in memory. The only writes
// done here are message purges and backups, which soju doesn't cache.
type Store struct {
	Path      string
	BackupDir string
	db        *sql.DB
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

// Same time layout soju uses for the Message.time column.
const sqliteTimeLayout = "2006-01-02T15:04:05.000Z"

func OpenStore(path, backupDir string) (*Store, error) {
	// No journal_mode pragma: soju already set WAL, which is persistent.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(15000)&_pragma=foreign_keys(true)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetConnMaxIdleTime(30 * time.Second)
	return &Store{Path: path, BackupDir: backupDir, db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// CheckAdmin validates credentials against the User table: only enabled
// soju admins with a password may log into the panel.
func (s *Store) CheckAdmin(ctx context.Context, username, password string) error {
	var hash sql.NullString
	var admin, enabled bool
	err := s.db.QueryRowContext(ctx,
		`SELECT password, admin, enabled FROM User WHERE username = ?`, username,
	).Scan(&hash, &admin, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn comparable time so unknown usernames can't be told apart.
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return errors.New("invalid credentials")
	} else if err != nil {
		return err
	}
	if !hash.Valid || hash.String == "" {
		return errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash.String), []byte(password)); err != nil {
		return errors.New("invalid credentials")
	}
	if !admin || !enabled {
		return errors.New("user is not a soju admin or is disabled")
	}
	return nil
}

type User struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Admin       bool   `json:"admin"`
	Enabled     bool   `json:"enabled"`
	Nick        string `json:"nick"`
	Realname    string `json:"realname"`
	CreatedAt   string `json:"created_at"`
	MaxNetworks int64  `json:"max_networks"`
	HasPassword bool   `json:"has_password"`
	Networks    int64  `json:"networks"`
	LastSeen    string `json:"last_seen"`
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.username, u.admin, u.enabled, COALESCE(u.nick, ''), COALESCE(u.realname, ''),
			u.created_at, u.max_networks, COALESCE(u.password, '') != '',
			(SELECT COUNT(*) FROM Network n WHERE n.user = u.id),
			COALESCE(u.downstream_interacted_at, '')
		FROM User u ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Admin, &u.Enabled, &u.Nick, &u.Realname,
			&u.CreatedAt, &u.MaxNetworks, &u.HasPassword, &u.Networks, &u.LastSeen); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

type Network struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	DisplayName     string   `json:"display_name"`
	Addr            string   `json:"addr"`
	Nick            string   `json:"nick"`
	Username        string   `json:"username"`
	Realname        string   `json:"realname"`
	CertFP          string   `json:"certfp"`
	HasPass         bool     `json:"has_pass"`
	ConnectCommands []string `json:"connect_commands"`
	SASLMechanism   string   `json:"sasl_mechanism"`
	SASLUsername    string   `json:"sasl_username"`
	AutoAway        bool     `json:"auto_away"`
	Enabled         bool     `json:"enabled"`
	Channels        int64    `json:"channels"`
}

func (s *Store) Networks(ctx context.Context, username string) ([]Network, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT n.id, COALESCE(n.name, ''), n.addr, COALESCE(n.nick, ''), COALESCE(n.username, ''),
			COALESCE(n.realname, ''), COALESCE(n.certfp, ''), COALESCE(n.pass, '') != '',
			COALESCE(n.connect_commands, ''), COALESCE(n.sasl_mechanism, ''),
			COALESCE(n.sasl_plain_username, ''), n.auto_away, n.enabled,
			(SELECT COUNT(*) FROM Channel c WHERE c.network = n.id)
		FROM Network n JOIN User u ON u.id = n.user
		WHERE u.username = ? ORDER BY n.id`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nets := []Network{}
	for rows.Next() {
		var n Network
		var cmds string
		if err := rows.Scan(&n.ID, &n.Name, &n.Addr, &n.Nick, &n.Username, &n.Realname, &n.CertFP,
			&n.HasPass, &cmds, &n.SASLMechanism, &n.SASLUsername, &n.AutoAway, &n.Enabled, &n.Channels); err != nil {
			return nil, err
		}
		n.ConnectCommands = []string{}
		if cmds != "" {
			n.ConnectCommands = strings.Split(cmds, "\r\n")
		}
		// soju's network.GetName(): the name, or the address when unnamed.
		n.DisplayName = n.Name
		if n.DisplayName == "" {
			n.DisplayName = n.Addr
		}
		nets = append(nets, n)
	}
	return nets, rows.Err()
}

type Channel struct {
	Name          string `json:"name"`
	HasKey        bool   `json:"has_key"`
	Detached      bool   `json:"detached"`
	RelayDetached string `json:"relay_detached"`
	ReattachOn    string `json:"reattach_on"`
	DetachAfter   int64  `json:"detach_after"`
	DetachOn      string `json:"detach_on"`
}

var filterNames = []string{"default", "none", "highlight", "message"}

func filterName(v int) string {
	if v >= 0 && v < len(filterNames) {
		return filterNames[v]
	}
	return "default"
}

func (s *Store) Channels(ctx context.Context, networkID int64) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, COALESCE(key, '') != '', detached, relay_detached, reattach_on, detach_after, detach_on
		FROM Channel WHERE network = ? ORDER BY name`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chans := []Channel{}
	for rows.Next() {
		var c Channel
		var relay, reattach, detachOn int
		if err := rows.Scan(&c.Name, &c.HasKey, &c.Detached, &relay, &reattach, &c.DetachAfter, &detachOn); err != nil {
			return nil, err
		}
		c.RelayDetached, c.ReattachOn, c.DetachOn = filterName(relay), filterName(reattach), filterName(detachOn)
		chans = append(chans, c)
	}
	return chans, rows.Err()
}

type TargetStats struct {
	TargetID  int64  `json:"target_id"`
	NetworkID int64  `json:"network_id"`
	Network   string `json:"network"`
	Username  string `json:"username"`
	Target    string `json:"target"`
	Messages  int64  `json:"messages"`
	Oldest    string `json:"oldest"`
	Newest    string `json:"newest"`
}

type DBStats struct {
	FileSize     int64         `json:"file_size"`
	WALSize      int64         `json:"wal_size"`
	PageSize     int64         `json:"page_size"`
	PageCount    int64         `json:"page_count"`
	FreePages    int64         `json:"free_pages"`
	Messages     int64         `json:"messages"`
	Targets      []TargetStats `json:"targets"`
	JournalMode  string        `json:"journal_mode"`
	SQLite       string        `json:"sqlite_version"`
	VolumeFree   int64         `json:"volume_free"`
	VolumeTotal  int64         `json:"volume_total"`
	BackupsBytes int64         `json:"backups_bytes"`
}

func (s *Store) Stats(ctx context.Context) (*DBStats, error) {
	st := &DBStats{Targets: []TargetStats{}}
	if fi, err := os.Stat(s.Path); err == nil {
		st.FileSize = fi.Size()
	}
	if fi, err := os.Stat(s.Path + "-wal"); err == nil {
		st.WALSize = fi.Size()
	}
	st.VolumeFree, st.VolumeTotal = diskUsage(filepath.Dir(s.Path))
	if bs, err := s.Backups(); err == nil {
		for _, b := range bs {
			st.BackupsBytes += b.Size
		}
	}

	for _, q := range []struct {
		sql  string
		dest any
	}{
		{"PRAGMA page_size", &st.PageSize},
		{"PRAGMA page_count", &st.PageCount},
		{"PRAGMA freelist_count", &st.FreePages},
		{"PRAGMA journal_mode", &st.JournalMode},
		{"SELECT sqlite_version()", &st.SQLite},
	} {
		if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dest); err != nil {
			return nil, fmt.Errorf("%v: %w", q.sql, err)
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, t.network, COALESCE(n.name, n.addr, '?'), COALESCE(u.username, '?'), t.target,
			s.cnt, s.oldest, s.newest
		FROM (SELECT target, COUNT(*) AS cnt, MIN(time) AS oldest, MAX(time) AS newest
			FROM Message GROUP BY target) s
		JOIN MessageTarget t ON t.id = s.target
		LEFT JOIN Network n ON n.id = t.network
		LEFT JOIN User u ON u.id = n.user`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t TargetStats
		if err := rows.Scan(&t.TargetID, &t.NetworkID, &t.Network, &t.Username, &t.Target,
			&t.Messages, &t.Oldest, &t.Newest); err != nil {
			return nil, err
		}
		st.Messages += t.Messages
		st.Targets = append(st.Targets, t)
	}
	sort.Slice(st.Targets, func(i, j int) bool { return st.Targets[i].Messages > st.Targets[j].Messages })
	return st, rows.Err()
}

// PurgeFilter selects messages to delete. Zero values mean "any".
type PurgeFilter struct {
	NetworkID     int64 `json:"network_id"`
	TargetID      int64 `json:"target_id"`
	OlderThanDays int   `json:"older_than_days"`
}

func (f PurgeFilter) where() (string, []any) {
	var conds []string
	var args []any
	if f.TargetID != 0 {
		conds = append(conds, "target = ?")
		args = append(args, f.TargetID)
	} else if f.NetworkID != 0 {
		conds = append(conds, "target IN (SELECT id FROM MessageTarget WHERE network = ?)")
		args = append(args, f.NetworkID)
	}
	if f.OlderThanDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -f.OlderThanDays).Format(sqliteTimeLayout)
		conds = append(conds, "time < ?")
		args = append(args, cutoff)
	}
	if len(conds) == 0 {
		return "1", nil
	}
	return strings.Join(conds, " AND "), args
}

func (s *Store) PurgeCount(ctx context.Context, f PurgeFilter) (int64, error) {
	where, args := f.where()
	var n int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM Message WHERE "+where, args...).Scan(&n)
	return n, err
}

// Purge deletes in small batches so soju's own writes never wait on our
// lock for more than a moment. MessageTarget rows are kept: soju looks
// them up by (network, target) and re-uses them.
func (s *Store) Purge(ctx context.Context, f PurgeFilter, progress func(deleted int64)) (int64, error) {
	where, args := f.where()
	q := "DELETE FROM Message WHERE id IN (SELECT id FROM Message WHERE " + where + " LIMIT 2000)"
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		res, err := s.db.ExecContext(ctx, q, args...)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if progress != nil {
			progress(total)
		}
		if n == 0 {
			return total, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *Store) Vacuum(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "INSERT INTO MessageFTS(MessageFTS) VALUES('optimize')"); err != nil {
		return fmt.Errorf("optimize FTS: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	_, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

func (s *Store) IntegrityCheck(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		out = append(out, line)
	}
	return out, rows.Err()
}

type Backup struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

func (s *Store) Backup(ctx context.Context, reason string) (*Backup, error) {
	if err := os.MkdirAll(s.BackupDir, 0o700); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("soju-%s-%s.db", time.Now().UTC().Format("20060102-150405"), reason)
	dst := filepath.Join(s.BackupDir, name)
	// VACUUM INTO produces a consistent, compacted snapshot while soju keeps running.
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		os.Remove(dst)
		return nil, fmt.Errorf("backup: %w", err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		return nil, err
	}
	return &Backup{Name: name, Size: fi.Size(), ModTime: fi.ModTime().UTC().Format(time.RFC3339)}, nil
}

func (s *Store) Backups() ([]Backup, error) {
	entries, err := os.ReadDir(s.BackupDir)
	if errors.Is(err, os.ErrNotExist) {
		return []Backup{}, nil
	} else if err != nil {
		return nil, err
	}
	out := []Backup{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Backup{Name: e.Name(), Size: fi.Size(), ModTime: fi.ModTime().UTC().Format(time.RFC3339)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// BackupPath resolves a backup name, refusing anything that isn't a plain
// file name inside the backup directory.
func (s *Store) BackupPath(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || !strings.HasSuffix(name, ".db") || strings.HasPrefix(name, ".") {
		return "", errors.New("invalid backup name")
	}
	p := filepath.Join(s.BackupDir, name)
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

// PruneBackups keeps the newest `keep` backups.
func (s *Store) PruneBackups(keep int) {
	bs, err := s.Backups()
	if err != nil || keep <= 0 {
		return
	}
	for i := keep; i < len(bs); i++ {
		os.Remove(filepath.Join(s.BackupDir, bs[i].Name))
	}
}
