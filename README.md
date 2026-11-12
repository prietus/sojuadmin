# soju-admin

Web panel for a [soju](https://soju.im) v0.11.x IRC bouncer. Designed to run as a **sidecar** in soju's Kubernetes pod; it also runs under systemd, Podman or Docker Compose with a few features disabled (see [Running outside Kubernetes](#running-outside-kubernetes)).

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

## Running outside Kubernetes

soju-admin also runs as a plain binary (systemd) or next to soju in a Podman pod or Docker Compose project. Most of it only needs the admin socket and the database file, but two features rely on the Kubernetes API and are disabled without it. At startup the log says `no Kubernetes API (logs and config editing disabled)`.

| Feature | Outside Kubernetes |
|---|---|
| Users, networks, channels, SASL, notices, debug, console | Works (admin socket) |
| Database stats, purge, VACUUM, integrity check, backups | Works (direct file access) |
| Login | Works (soju's `User` table) |
| Reload / restart soju | Works if the panel can see and signal the soju process (see below) |
| Editing the config and MOTD | **Read only**: saving writes to the ConfigMap |
| Logs | **Unavailable**: they come from `pods/log` |
| Pod card on the overview | Not shown |

### Reload and restart

The panel finds the `soju` process in `/proc` and sends it signals: SIGHUP to reload, SIGTERM to restart. A restart only works if something brings soju back up after it exits cleanly:

- **systemd on the same host**: the panel sees soju's process as is. Run both as the same user (`User=soju`) so it may signal soju, and set `Restart=always` in `soju.service`. `Restart=on-failure` is not enough, because soju exits with status 0 on SIGTERM.
- **Podman pod**: containers in a pod don't share processes by default. Create the pod with `podman pod create --share +pid`, run soju with `--restart=always`, and mount soju's data directory in both containers.
- **Docker Compose**: give the panel `pid: "service:soju"`, give soju `restart: always`, and share the data volume.

### systemd example

The defaults match the container layout; soju's usual Linux packaging uses other paths:

```ini
[Unit]
Description=soju-admin web panel
After=soju.service

[Service]
User=soju
Environment=LISTEN=127.0.0.1:8090
Environment=SOJU_ADMIN_SOCKET=/run/soju/admin
Environment=SOJU_DB=/var/lib/soju/main.db
Environment=BACKUP_DIR=/var/lib/soju/backups
Environment=SOJU_CONFIG=/etc/soju/config
ExecStart=/usr/local/bin/sojuadmin
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Build the binary with `go install github.com/prietus/sojuadmin@latest` (or `go build`). Put a TLS reverse proxy such as Caddy or nginx in front of it; serving it over plain http requires `SECURE_COOKIE=false`, or the session cookie is never sent.

## Per-user upstream IPv6

soju's `upstream-user-ip` gives every user its own source address towards IRC networks, so one user's ban doesn't hit everyone. soju doesn't configure any addresses itself: it computes **range base + (user ID + 1)** and binds to it, so with `upstream-user-ip 2001:db8:0:1:50:7a::/96` user ID 1 connects from `…:50:7a:0:2`, ID 2 from `…:0:3`, ID 9 from `…:0:a` (hex). If that address isn't assigned on the host, the user can't connect.

The panel shows each user's ID and outgoing address on the Users page, marked **active** (soju has connections from it), **idle**, or **missing on host**, which is the state a newly created user lands in until its address is added.

A setup that works with a /64 routed to the LAN (e.g. via radvd):

1. **Pick a sub-range** away from SLAAC addresses, e.g. a /96 inside your /64.
2. **Assign a pool of addresses on one node** with [`deploy/soju-ipv6.service`](deploy/soju-ipv6.service): set `PREFIX`, `IFACE` and `LAST_ID`, install it under `/etc/systemd/system/` and `systemctl enable --now soju-ipv6`. It adds the addresses with `preferred_lft 0`, so the node keeps using its own address for its traffic and only explicit binds (soju) use them. To grow the pool, raise `LAST_ID` and run `systemctl daemon-reload && systemctl reload soju-ipv6`; **don't restart it**, since stopping removes the addresses and drops soju's live connections.
3. **Run soju on that node's network** with [`deploy/ipv6-hostnetwork.yaml`](deploy/ipv6-hostnetwork.yaml): `hostNetwork: true`, pinned to the node, with `dnsPolicy: ClusterFirstWithHostNet` so cluster service names still resolve. Check that soju's ports (6667, 8080) and the panel's (8090) are free on the node first. If that node goes down, soju stays down until you change the selector.
4. **Set the range** in the config (Configuration → Proxies & networking → Per-user outgoing IP ranges) and restart soju once.

Reverse DNS for those addresses is up to whoever delegates the reverse zone for your prefix. Many IRC networks also ban IPv6 per /64, so per-user addresses separate users' identities but don't guarantee a ban stays limited to one of them.

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
