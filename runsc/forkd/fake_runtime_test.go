// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package forkd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// fakeRuntime runs real host processes instead of sandboxes, so that the
// server's exit watching, limits and cleanup are tested without KVM. A fake
// child is a shell that the entries of ForkSpec.Env control:
//
//	FAKE_EXIT=<n>         exit with status n after FAKE_SLEEP_MS
//	FAKE_SLEEP_MS=<ms>    run for that long (default: until killed)
//	FAKE_WRITE=<bytes>    write that many bytes to stdout first
type fakeRuntime struct {
	mu        sync.Mutex
	templates []*fakeTemplate
	resets    int
	failFork  error
}

func (r *fakeRuntime) Platform() string { return "kvm" }

func (r *fakeRuntime) Reset() error {
	r.mu.Lock()
	r.resets++
	r.mu.Unlock()
	return nil
}

func (r *fakeRuntime) CreateTemplate(ts TemplateSpec) (Template, error) {
	cmd := exec.Command("sleep", "3600")
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	t := &fakeTemplate{rt: r, spec: ts, cmd: cmd}
	go cmd.Wait()
	r.mu.Lock()
	r.templates = append(r.templates, t)
	r.mu.Unlock()
	return t, nil
}

type fakeTemplate struct {
	rt        *fakeRuntime
	spec      TemplateSpec
	cmd       *exec.Cmd
	mu        sync.Mutex
	children  []*fakeChild
	destroyed bool
}

func (t *fakeTemplate) PID() int { return t.cmd.Process.Pid }

func (t *fakeTemplate) Destroy() error {
	t.mu.Lock()
	t.destroyed = true
	kids := append([]*fakeChild(nil), t.children...)
	t.mu.Unlock()
	for _, c := range kids {
		c.Destroy()
	}
	_ = t.cmd.Process.Kill()
	return nil
}

func envValue(env []string, name string) string {
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, name+"="); ok {
			return v
		}
	}
	return ""
}

func (t *fakeTemplate) Fork(fs ForkSpec) (Child, error) {
	if err := t.rt.failFork; err != nil {
		return nil, err
	}
	script := ""
	if n := envValue(fs.Env, "FAKE_WRITE"); n != "" {
		script += fmt.Sprintf("head -c %s /dev/zero | tr '\\0' x; ", n)
	}
	sleepMS := envValue(fs.Env, "FAKE_SLEEP_MS")
	if sleepMS == "" {
		script += "exec sleep 3600"
	} else {
		ms, _ := strconv.Atoi(sleepMS)
		script += fmt.Sprintf("sleep %d.%03d; exit %s", ms/1000, ms%1000, envValue(fs.Env, "FAKE_EXIT"))
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Stdout, cmd.Stderr = fs.Stdout, fs.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if fs.CgroupPath != "" {
		// What the real fork does: the child moves into its cgroup first.
		procs := filepath.Join(cgroupMount, fs.CgroupPath, "cgroup.procs")
		if err := os.WriteFile(procs, []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return nil, err
		}
	}
	c := &fakeChild{cmd: cmd, spec: fs, done: make(chan struct{})}
	go func() {
		c.err = cmd.Wait()
		close(c.done)
	}()
	t.mu.Lock()
	t.children = append(t.children, c)
	t.mu.Unlock()
	return c, nil
}

type fakeChild struct {
	cmd  *exec.Cmd
	spec ForkSpec
	done chan struct{}
	err  error
}

func (c *fakeChild) PID() int { return c.cmd.Process.Pid }

func (c *fakeChild) Wait() (WaitStatus, error) {
	<-c.done
	if c.err == nil {
		return WaitStatus{Exited: true}, nil
	}
	if ee, ok := c.err.(*exec.ExitError); ok {
		ws := ee.Sys().(syscall.WaitStatus)
		if ws.Exited() {
			return WaitStatus{Exited: true, ExitCode: ws.ExitStatus()}, nil
		}
		// A real sandbox that is killed does not answer: report it the same way.
		return WaitStatus{}, fmt.Errorf("killed by %v", ws.Signal())
	}
	return WaitStatus{}, c.err
}

func (c *fakeChild) Destroy() error {
	_ = c.cmd.Process.Kill()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
	}
	return nil
}
