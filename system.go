package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// --- soju process control -------------------------------------------------
//
// Requires shareProcessNamespace: true on the pod, so the sidecar sees soju's
// process. SIGHUP makes soju reload its config; SIGTERM shuts it down
// gracefully and the kubelet restarts the container (restartPolicy: Always)
// without recreating the pod.

func findSojuPID() (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || len(cmdline) == 0 {
			continue
		}
		argv0 := string(bytes.SplitN(cmdline, []byte{0}, 2)[0])
		if filepath.Base(argv0) == "soju" {
			return pid, nil
		}
	}
	return 0, errors.New("soju process not found (is shareProcessNamespace: true set?)")
}

type ProcInfo struct {
	PID      int    `json:"pid"`
	Started  string `json:"started"`
	RSSBytes int64  `json:"rss_bytes"`
	Threads  int    `json:"threads"`
}

func sojuProcInfo() (*ProcInfo, error) {
	pid, err := findSojuPID()
	if err != nil {
		return nil, err
	}
	info := &ProcInfo{PID: pid}
	if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "VmRSS:":
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				info.RSSBytes = kb * 1024
			case "Threads:":
				info.Threads, _ = strconv.Atoi(f[1])
			}
		}
	}
	if fi, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
		info.Started = fi.ModTime().UTC().Format(time.RFC3339)
	}
	return info, nil
}

func signalSoju(sig syscall.Signal) (int, error) {
	pid, err := findSojuPID()
	if err != nil {
		return 0, err
	}
	return pid, syscall.Kill(pid, sig)
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// restartSoju stops soju gracefully and waits for the kubelet to bring it
// back with a working admin socket.
func restartSoju(ctx context.Context, b *Bouncer, log func(string, ...any)) error {
	pid, err := signalSoju(syscall.SIGTERM)
	if err != nil {
		return err
	}
	log("sent SIGTERM to soju (pid %d)", pid)

	for processAlive(pid) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(250 * time.Millisecond)
	}
	log("soju has stopped")

	// A stale socket makes the new soju exit with "address already in use"
	// (the pod's init container only cleans it when the whole pod restarts).
	if _, err := os.Stat(b.SocketPath); err == nil {
		if c, err := net.DialTimeout("unix", b.SocketPath, time.Second); err != nil {
			os.Remove(b.SocketPath)
			log("removed stale admin socket")
		} else {
			c.Close()
		}
	}

	log("waiting for the kubelet to restart the container…")
	for {
		if ctx.Err() != nil {
			return fmt.Errorf("soju no ha vuelto a tiempo: %w", ctx.Err())
		}
		if newPID, err := findSojuPID(); err == nil && newPID != pid {
			if err := b.Ping(ctx); err == nil {
				log("soju is back up (pid %d)", newPID)
				return nil
			}
		}
		time.Sleep(time.Second)
	}
}

// watchStaleSocket removes the admin socket whenever soju isn't running, so
// a crashed or OOM-killed soju doesn't come back to "address already in use".
func watchStaleSocket(path string) {
	if _, err := os.Stat("/proc/self"); err != nil {
		return // no procfs (local development)
	}
	for range time.Tick(2 * time.Second) {
		if _, err := findSojuPID(); err == nil {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			if err := os.Remove(path); err == nil {
				log.Printf("soju is not running: removed stale admin socket %s", path)
			}
		}
	}
}

func diskUsage(path string) (free, total int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize)
}

// dropPrivileges switches to the owner of soju's database so that any
// file we create (WAL, backups) stays writable by soju.
func dropPrivileges(dbPath string) (string, error) {
	if os.Geteuid() != 0 {
		return fmt.Sprintf("uid %d", os.Geteuid()), nil
	}
	fi, err := os.Stat(dbPath)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return "root (soju.db is owned by root)", nil
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return "", err
	}
	if err := syscall.Setgid(int(st.Gid)); err != nil {
		return "", err
	}
	if err := syscall.Setuid(int(st.Uid)); err != nil {
		return "", err
	}
	return fmt.Sprintf("uid %d gid %d (owner of soju.db)", st.Uid, st.Gid), nil
}

// --- Kubernetes API (in-cluster, minimal) ---------------------------------

type Kube struct {
	base      string
	namespace string
	client    *http.Client
	tokenPath string
}

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

func NewKube() (*Kube, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, errors.New("not running inside Kubernetes")
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("no ServiceAccount mounted: %w", err)
	}
	ns, err := os.ReadFile(saDir + "/namespace")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return &Kube{
		base:      "https://" + net.JoinHostPort(host, port),
		namespace: strings.TrimSpace(string(ns)),
		tokenPath: saDir + "/token",
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		},
	}, nil
}

func (k *Kube) do(ctx context.Context, method, path, contentType string, body io.Reader) ([]byte, error) {
	token, err := os.ReadFile(k.tokenPath) // re-read: projected tokens rotate
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var status struct{ Message string }
		if json.Unmarshal(data, &status) == nil && status.Message != "" {
			return nil, fmt.Errorf("kubernetes %d: %s", resp.StatusCode, status.Message)
		}
		return nil, fmt.Errorf("kubernetes %d", resp.StatusCode)
	}
	return data, nil
}

func (k *Kube) ConfigMapKey(ctx context.Context, name, key string) (string, error) {
	data, err := k.do(ctx, "GET", fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", k.namespace, url.PathEscape(name)), "", nil)
	if err != nil {
		return "", err
	}
	var cm struct{ Data map[string]string }
	if err := json.Unmarshal(data, &cm); err != nil {
		return "", err
	}
	v, ok := cm.Data[key]
	if !ok {
		return "", fmt.Errorf("ConfigMap %s has no key %q", name, key)
	}
	return v, nil
}

func (k *Kube) SetConfigMapKey(ctx context.Context, name, key, value string) error {
	patch, _ := json.Marshal(map[string]any{"data": map[string]string{key: value}})
	_, err := k.do(ctx, "PATCH", fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", k.namespace, url.PathEscape(name)),
		"application/merge-patch+json", bytes.NewReader(patch))
	return err
}

func (k *Kube) PodLogs(ctx context.Context, pod, container string, tail int, previous bool) (string, error) {
	q := url.Values{}
	q.Set("container", container)
	q.Set("tailLines", strconv.Itoa(tail))
	q.Set("timestamps", "true")
	if previous {
		q.Set("previous", "true")
	}
	data, err := k.do(ctx, "GET", fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?%s", k.namespace, url.PathEscape(pod), q.Encode()), "", nil)
	return string(data), err
}

type ContainerStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restart_count"`
	Image        string `json:"image"`
	State        string `json:"state"`
	Since        string `json:"since"`
	LastExit     string `json:"last_exit"`
}

type PodInfo struct {
	Name       string            `json:"name"`
	Node       string            `json:"node"`
	Phase      string            `json:"phase"`
	StartTime  string            `json:"start_time"`
	Containers []ContainerStatus `json:"containers"`
}

func (k *Kube) Pod(ctx context.Context, name string) (*PodInfo, error) {
	data, err := k.do(ctx, "GET", fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", k.namespace, url.PathEscape(name)), "", nil)
	if err != nil {
		return nil, err
	}
	var pod struct {
		Spec   struct{ NodeName string }
		Status struct {
			Phase             string
			StartTime         string
			ContainerStatuses []struct {
				Name         string
				Ready        bool
				RestartCount int
				Image        string
				State        map[string]struct {
					StartedAt string
					Reason    string
				}
				LastState struct {
					Terminated *struct {
						Reason   string
						ExitCode int
						Finished string `json:"finishedAt"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(data, &pod); err != nil {
		return nil, err
	}
	info := &PodInfo{Name: name, Node: pod.Spec.NodeName, Phase: pod.Status.Phase, StartTime: pod.Status.StartTime}
	for _, cs := range pod.Status.ContainerStatuses {
		c := ContainerStatus{Name: cs.Name, Ready: cs.Ready, RestartCount: cs.RestartCount, Image: cs.Image}
		for state, v := range cs.State {
			c.State, c.Since = state, v.StartedAt
			if v.Reason != "" {
				c.State += " (" + v.Reason + ")"
			}
		}
		if t := cs.LastState.Terminated; t != nil {
			c.LastExit = fmt.Sprintf("%s, exit code %d, %s", t.Reason, t.ExitCode, t.Finished)
		}
		info.Containers = append(info.Containers, c)
	}
	return info, nil
}
