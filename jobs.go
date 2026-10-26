package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Jobs runs long operations (restart, purge, vacuum, backups, config apply)
// one at a time in the background; the UI polls their log.
type Jobs struct {
	mu      sync.Mutex
	nextID  int
	jobs    []*Job
	running *Job
}

// JobView is the JSON-friendly copy of a Job handed to the UI.
type JobView struct {
	ID       int       `json:"id"`
	Kind     string    `json:"kind"`
	User     string    `json:"user"`
	Status   string    `json:"status"` // running, done, failed
	Log      []string  `json:"log"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
}

type Job struct {
	JobView
	mu sync.Mutex
}

var errBusy = errors.New("another operation is already running")

func (j *Job) Logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	j.mu.Lock()
	j.Log = append(j.Log, time.Now().UTC().Format("15:04:05")+"  "+line)
	j.mu.Unlock()
	log.Printf("job %d (%s): %s", j.ID, j.Kind, line)
}

func (j *Job) snapshot() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	v := j.JobView
	v.Log = append([]string{}, j.Log...)
	return v
}

func (js *Jobs) Start(kind, user string, timeout time.Duration, fn func(ctx context.Context, j *Job) error) (*JobView, error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.running != nil {
		return nil, fmt.Errorf("%w: %s (#%d)", errBusy, js.running.Kind, js.running.ID)
	}
	js.nextID++
	j := &Job{JobView: JobView{ID: js.nextID, Kind: kind, User: user, Status: "running", Log: []string{}, Started: time.Now().UTC()}}
	js.jobs = append(js.jobs, j)
	if len(js.jobs) > 30 {
		js.jobs = js.jobs[len(js.jobs)-30:]
	}
	js.running = j

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := fn(ctx, j)
		j.mu.Lock()
		j.Finished = time.Now().UTC()
		if err != nil {
			j.Status, j.Error = "failed", err.Error()
		} else {
			j.Status = "done"
		}
		j.mu.Unlock()
		if err != nil {
			j.Logf("ERROR: %v", err)
		} else {
			j.Logf("finished")
		}
		js.mu.Lock()
		js.running = nil
		js.mu.Unlock()
	}()
	snap := j.snapshot()
	return &snap, nil
}

func (js *Jobs) Get(id int) (JobView, bool) {
	js.mu.Lock()
	defer js.mu.Unlock()
	for _, j := range js.jobs {
		if j.ID == id {
			return j.snapshot(), true
		}
	}
	return JobView{}, false
}

func (js *Jobs) List() []JobView {
	js.mu.Lock()
	defer js.mu.Unlock()
	out := make([]JobView, 0, len(js.jobs))
	for i := len(js.jobs) - 1; i >= 0; i-- {
		s := js.jobs[i].snapshot()
		s.Log = nil
		out = append(out, s)
	}
	return out
}
