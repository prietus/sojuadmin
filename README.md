# soju-admin

Web panel for a [soju](https://soju.im) v0.11.x IRC bouncer. Runs as a **sidecar** in soju's pod.

| Feature | How |
|---|---|
| Users, networks, channels, SASL, notices, debug, BouncerServ console | `unix+admin:///data/admin.sock`, the same protocol as `sojuctl` |
| Listings and stats | reads `/data/soju.db` directly |
| Message purge, VACUUM, integrity check, backups | direct SQLite in small batches (WAL, `busy_timeout`); backups via `VACUUM INTO` into `/data/backups` |
| Reload config / restart soju | SIGHUP / SIGTERM to the soju process (`shareProcessNamespace`); the kubelet restarts only the container |
| Configuration | form editor (or raw file) for every soju v0.11 directive, validated server-side and saved to the `soju-config` ConfigMap; comments and untouched lines are preserved, and a diff is shown before applying. The message of the day is edited as text and stored as a second ConfigMap key |
| Logs | Kubernetes API (`pods/log`) |

Sign in with any **enabled admin** soju user (bcrypt check against the `User` table).
Every mutating action is logged by the container as `audit: ...`.

## Build

```sh
docker buildx build --platform linux/amd64 --build-arg VERSION=x.y.z -t prietus/soju-admin:x.y.z --push .
```

## Deploy

```sh
kubectl apply -f deploy/rbac.yaml
kubectl -n soju patch deployment soju --patch-file deploy/sidecar-patch.yaml   # recreates the pod (Recreate strategy)
kubectl apply -f deploy/ingress.local.yaml   # copy of ingress.yaml with your hostname
```

Without an ingress: `kubectl -n soju port-forward svc/soju-admin 8090` and open http://localhost:8090
(set `SECURE_COOKIE=false` on the sidecar, otherwise the session cookie isn't sent over plain http).

## Environment

| Variable | Default |
|---|---|
| `LISTEN` | `:8090` |
| `SOJU_DATA_DIR` | `/data` |
| `SOJU_ADMIN_SOCKET` | `$SOJU_DATA_DIR/admin.sock` |
| `SOJU_DB` | `$SOJU_DATA_DIR/soju.db` |
| `BACKUP_DIR` / `KEEP_BACKUPS` | `$SOJU_DATA_DIR/backups` / `10` |
| `SOJU_CONFIG` | `/etc/soju/config` |
| `SOJU_CONFIGMAP` / `SOJU_CONFIGMAP_KEY` | empty (editing disabled) / `config` |
| `SOJU_MOTD_KEY` | `motd` (stored in the same ConfigMap, shows up as `/etc/soju/motd`) |
| `POD_NAME`, `SOJU_CONTAINER` | downward API / `soju` |
| `SECURE_COOKIE` | `true` |

## Notes

- The sidecar starts as root and immediately switches to the uid/gid owning `soju.db`, so WAL and backup files stay writable by soju.
- When soju isn't running, the sidecar removes a stale `admin.sock`, so soju doesn't crash-loop with "address already in use" after an OOM kill or crash.
- soju refuses to start on unknown or repeated directives (only `listen` and `auth` may repeat). The panel blocks saving such configs, and never lets you drop the admin socket listener it depends on.
- Restoring a backup: `kubectl -n soju scale deploy/soju --replicas=0`, copy the backup over `soju.db` with a temporary pod mounting the PVC, then scale back to 1.
