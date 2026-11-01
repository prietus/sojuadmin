// soju-admin is a web panel for a soju IRC bouncer, meant to run as a
// sidecar in soju's pod: it shares /data (admin socket + SQLite database)
// and the process namespace (to reload/restart soju with signals).
package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var version = "dev"

//go:embed web
var webFS embed.FS

type Config struct {
	Listen        string
	DataDir       string
	SocketPath    string
	DBPath        string
	BackupDir     string
	KeepBackups   int
	SojuConfig    string
	ConfigMap     string
	ConfigMapKey  string
	MotdKey       string
	MotdPath      string
	PodName       string
	SojuContainer string
	SecureCookie  bool
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	data := env("SOJU_DATA_DIR", "/data")
	sojuConfig := env("SOJU_CONFIG", "/etc/soju/config")
	motdKey := env("SOJU_MOTD_KEY", "motd")
	keep, _ := strconv.Atoi(env("KEEP_BACKUPS", "10"))
	return Config{
		Listen:       env("LISTEN", ":8090"),
		DataDir:      data,
		SocketPath:   env("SOJU_ADMIN_SOCKET", filepath.Join(data, "admin.sock")),
		DBPath:       env("SOJU_DB", filepath.Join(data, "soju.db")),
		BackupDir:    env("BACKUP_DIR", filepath.Join(data, "backups")),
		KeepBackups:  keep,
		SojuConfig:   sojuConfig,
		ConfigMap:    os.Getenv("SOJU_CONFIGMAP"),
		ConfigMapKey: env("SOJU_CONFIGMAP_KEY", "config"),
		// The ConfigMap is mounted as a directory, so its MOTD key shows up
		// as a file next to the config.
		MotdKey:       motdKey,
		MotdPath:      filepath.Join(filepath.Dir(sojuConfig), motdKey),
		PodName:       os.Getenv("POD_NAME"),
		SojuContainer: env("SOJU_CONTAINER", "soju"),
		SecureCookie:  env("SECURE_COOKIE", "true") == "true",
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg := loadConfig()

	privs, err := dropPrivileges(cfg.DBPath)
	if err != nil {
		log.Fatalf("cannot adjust privileges: %v", err)
	}

	store, err := OpenStore(cfg.DBPath, cfg.BackupDir)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer store.Close()

	app := &App{
		cfg:      cfg,
		bouncer:  &Bouncer{SocketPath: cfg.SocketPath, Timeout: 30 * time.Second},
		store:    store,
		sessions: NewSessions(12*time.Hour, cfg.SecureCookie),
		jobs:     &Jobs{},
		privs:    privs,
	}
	if k, err := NewKube(); err != nil {
		log.Printf("no Kubernetes API (logs and config editing disabled): %v", err)
	} else {
		app.kube = k
	}

	go watchStaleSocket(cfg.SocketPath)

	mux := http.NewServeMux()
	app.routes(mux)
	static, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("soju-admin %s listening on %s (socket %s, db %s, %s)", version, cfg.Listen, cfg.SocketPath, cfg.DBPath, privs)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
