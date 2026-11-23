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
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// child is a forked sandbox and everything that forkd made for it.
type child struct {
	id     string
	seedID string
	dir    string

	rt     Child
	cg     *childCgroup
	vnet   *vethNet
	stdout *os.File
	stderr *os.File

	maxLifetime time.Duration
	logLimit    int64

	mu   sync.Mutex
	info ChildInfo
	// exit is set once the child is over; done closes then.
	exit *ExitInfo
	done chan struct{}
	// cleaned closes when the sandbox, cgroup and network are gone.
	cleaned chan struct{}
	// kill asks the supervisor to kill the child for a reason.
	killReason, killDetail string
	killCh                 chan struct{}
}

func (c *child) running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exit == nil
}

func (c *child) snapshot() ChildInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := c.info
	if c.exit != nil {
		info.State = StateExited
		e := *c.exit
		info.Exit = &e
	} else {
		info.State = StateRunning
	}
	return info
}

// setKill asks for the child to be killed. The first reason wins.
func (c *child) setKill(reason, detail string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.killReason != "" {
		return
	}
	c.killReason, c.killDetail = reason, detail
	close(c.killCh)
}

func (c *child) killRequest() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.killReason, c.killDetail
}

func (s *Server) validateFork(req *ForkRequest) *opError {
	if req == nil {
		return errf(CodeInvalidArgument, "fork request is missing")
	}
	if err := ValidID(req.SeedID); err != nil {
		return errf(CodeInvalidArgument, "seed_id: %v", err)
	}
	if err := ValidID(req.ChildID); err != nil {
		return errf(CodeInvalidArgument, "child_id: %v", err)
	}
	if err := s.validateEnv(req.Env); err != nil {
		return errf(CodeInvalidArgument, "env: %v", err)
	}
	if err := req.Cgroup.validate(!s.opt.AllowUnlimitedChildren); err != nil {
		return errf(CodeInvalidArgument, "cgroup: %v", err)
	}
	if req.Cgroup != nil && s.cg == nil {
		return errf(CodeFailedPrecondition, "cgroup limits need forkd to run with --cgroup-parent")
	}
	if req.Net != nil {
		if (req.Net.NetNSPath == "") == (req.Net.Veth == nil) {
			return errf(CodeInvalidArgument, "net needs exactly one of netns_path and veth")
		}
		if req.Net.NetNSPath != "" && !filepath.IsAbs(req.Net.NetNSPath) {
			return errf(CodeInvalidArgument, "net.netns_path must be absolute")
		}
		if req.Net.Veth != nil {
			if err := req.Net.Veth.validate(); err != nil {
				return errf(CodeInvalidArgument, "net.veth: %v", err)
			}
		}
	}
	if req.MaxLifetimeMS < 0 || req.LogBytesLimit < 0 {
		return errf(CodeInvalidArgument, "limits must not be negative")
	}
	return nil
}

// doFork forks one child. It returns after the child's guest runs.
func (s *Server) doFork(req *ForkRequest) (*ChildInfo, *opError) {
	t0 := time.Now()
	if oe := s.validateFork(req); oe != nil {
		return nil, oe
	}
	sd, oe := s.getSeed(req.SeedID)
	if oe != nil {
		return nil, oe
	}
	sd.mu.Lock()
	state := sd.info.State
	unusable := sd.creating || sd.dead || sd.deleting
	sd.mu.Unlock()
	if unusable || state != StateReady {
		return nil, errf(CodeFailedPrecondition, "seed %q is not ready", req.SeedID)
	}

	c := &child{
		id:      req.ChildID,
		seedID:  req.SeedID,
		info:    ChildInfo{ChildID: req.ChildID, SeedID: req.SeedID},
		done:    make(chan struct{}),
		cleaned: make(chan struct{}),
		killCh:  make(chan struct{}),
	}
	c.maxLifetime = time.Duration(req.MaxLifetimeMS) * time.Millisecond
	if c.maxLifetime == 0 {
		c.maxLifetime = s.opt.DefaultMaxLifetime
	}
	c.logLimit = req.LogBytesLimit
	if c.logLimit == 0 {
		c.logLimit = s.opt.DefaultLogBytesLimit
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errf(CodeUnavailable, "forkd is shutting down")
	}
	if _, dup := s.children[req.ChildID]; dup {
		s.mu.Unlock()
		return nil, errf(CodeAlreadyExists, "child %q exists", req.ChildID)
	}
	if len(s.children) >= s.opt.MaxRecords {
		s.mu.Unlock()
		return nil, errf(CodeResourceExhausted, "%d children, running or exited, are not deleted yet", len(s.children))
	}
	running := 0
	for _, o := range s.children {
		if o.running() {
			running++
		}
	}
	if running >= s.opt.MaxChildren {
		s.mu.Unlock()
		return nil, errf(CodeResourceExhausted, "%d children run, the limit is %d", running, s.opt.MaxChildren)
	}
	s.children[req.ChildID] = c
	s.mu.Unlock()
	// The seed learns of the child before the fork, so that deleting the seed
	// cannot miss it.
	sd.mu.Lock()
	if sd.deleting || sd.dead {
		sd.mu.Unlock()
		s.mu.Lock()
		delete(s.children, req.ChildID)
		s.mu.Unlock()
		return nil, errf(CodeFailedPrecondition, "seed %q is not ready", req.SeedID)
	}
	sd.children[req.ChildID] = c
	sd.mu.Unlock()

	undo := func(oe *opError) (*ChildInfo, *opError) {
		c.cleanup()
		if c.dir != "" {
			os.RemoveAll(c.dir)
		}
		s.mu.Lock()
		delete(s.children, req.ChildID)
		s.mu.Unlock()
		sd.mu.Lock()
		delete(sd.children, req.ChildID)
		sd.mu.Unlock()
		close(c.cleaned)
		return nil, oe
	}

	// Per-child files, cgroup and network exist before the fork: the child moves
	// into its cgroup and takes over its network before its guest runs.
	c.dir = filepath.Join(s.opt.StateDir, "children", req.ChildID)
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return undo(errf(CodeInternal, "%v", err))
	}
	var err error
	open := func(name string) (*os.File, error) {
		return os.OpenFile(filepath.Join(c.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	}
	if c.stdout, err = open("stdout.log"); err != nil {
		return undo(errf(CodeInternal, "%v", err))
	}
	if c.stderr, err = open("stderr.log"); err != nil {
		return undo(errf(CodeInternal, "%v", err))
	}
	cgroupPath := ""
	if s.cg != nil {
		if c.cg, err = s.cg.create(req.ChildID, req.Cgroup); err != nil {
			return undo(errf(CodeInternal, "%v", err))
		}
		cgroupPath = c.cg.relative()
	}
	netns, disableIPv6 := "", false
	if req.Net != nil {
		disableIPv6 = req.Net.DisableIPv6
		if req.Net.Veth != nil {
			if c.vnet, err = createVethNet(req.Net.Veth); err != nil {
				return undo(errf(CodeInternal, "creating the network: %v", err))
			}
			netns = c.vnet.path()
		} else {
			netns = req.Net.NetNSPath
		}
	}

	forkStart := time.Now()
	rtc, err := sd.tmpl.Fork(ForkSpec{
		ID:          req.ChildID,
		Dir:         c.dir,
		Env:         req.Env,
		CgroupPath:  cgroupPath,
		NetNSPath:   netns,
		DisableIPv6: disableIPv6,
		Stdout:      c.stdout,
		Stderr:      c.stderr,
	})
	if err != nil {
		code := CodeInternal
		if sd.snapshot().State != StateReady {
			code = CodeFailedPrecondition
		}
		return undo(errf(code, "fork: %v", err))
	}
	c.rt = rtc
	forkMS := float64(time.Since(forkStart).Microseconds()) / 1000.0

	var attestation []string
	if !s.opt.skipAttestation {
		var aerr error
		if attestation, aerr = attestChild(rtc.PID()); aerr != nil {
			_ = unix.Kill(rtc.PID(), unix.SIGKILL)
			return undo(errf(CodeFailedPrecondition, "%v", aerr))
		}
	}

	c.mu.Lock()
	c.info = ChildInfo{
		ChildID:     req.ChildID,
		SeedID:      req.SeedID,
		PID:         rtc.PID(),
		StdoutPath:  filepath.Join(c.dir, "stdout.log"),
		StderrPath:  filepath.Join(c.dir, "stderr.log"),
		NetNSPath:   netns,
		ForkMS:      forkMS,
		StartedUnix: time.Now().UnixMilli(),
		Attestation: attestation,
	}
	if c.cg != nil {
		c.info.CgroupPath = c.cg.dir
	}
	c.mu.Unlock()
	go s.supervise(sd, c)
	info := c.snapshot()
	info.ForkMS = float64(time.Since(t0).Microseconds()) / 1000.0
	return &info, nil
}

// cleanup releases the host resources of a child: the sandbox, the cgroup, the
// network and the open files. The log files stay until the child is deleted.
func (c *child) cleanup() {
	if c.rt != nil {
		_ = c.rt.Destroy()
	}
	c.cg.remove()
	c.vnet.destroy()
	for _, f := range []*os.File{c.stdout, c.stderr} {
		if f != nil {
			f.Close()
		}
	}
}

// logBytes is the size of the child's output so far.
func (c *child) logBytes() int64 {
	var total int64
	for _, name := range []string{"stdout.log", "stderr.log"} {
		if st, err := os.Stat(filepath.Join(c.dir, name)); err == nil {
			total += st.Size()
		}
	}
	return total
}

// supervise watches a child until it is over, kills it at its limits and
// records how it ended.
func (s *Server) supervise(sd *seed, c *child) {
	type waitResult struct {
		ws  WaitStatus
		err error
	}
	waited := make(chan waitResult, 1)
	go func() {
		ws, err := c.rt.Wait()
		waited <- waitResult{ws, err}
	}()

	pidfd, pidErr := unix.PidfdOpen(c.rt.PID(), 0)
	gone := make(chan struct{})
	if pidErr == nil {
		go func() {
			defer close(gone)
			fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
			for {
				n, err := unix.Poll(fds, -1)
				if err == unix.EINTR {
					continue
				}
				if err != nil || n > 0 {
					return
				}
			}
		}()
	} else {
		close(gone)
	}
	kill := func() {
		if pidErr == nil {
			_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		}
	}

	deadline := time.NewTimer(c.maxLifetime)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	var (
		result    waitResult
		haveWait  bool
		detail    string
		killed    bool
		killedFor string
	)
loop:
	for {
		select {
		case result = <-waited:
			haveWait = true
			break loop
		case <-gone:
			// The sandbox process ended. Give the status a moment to arrive; it
			// does not when the process was killed.
			select {
			case result = <-waited:
				haveWait = true
			case <-time.After(300 * time.Millisecond):
			}
			break loop
		case <-c.killCh:
			if !killed {
				killed = true
				killedFor, _ = c.killRequest()
				kill()
			}
		case <-deadline.C:
			if !killed {
				killed, killedFor, detail = true, ReasonMaxLifetime, fmt.Sprintf("the child ran for %v", c.maxLifetime)
				kill()
			}
		case <-tick.C:
			if !killed {
				if n := c.logBytes(); n > c.logLimit {
					killed, killedFor, detail = true, ReasonLogLimit, fmt.Sprintf("the child wrote %d bytes, the limit is %d", n, c.logLimit)
					kill()
				}
			}
		}
	}
	if pidErr == nil {
		defer unix.Close(pidfd)
	}

	exit := &ExitInfo{AtUnix: time.Now().UnixMilli(), Detail: detail}
	if c.cg != nil {
		exit.OOMKills = c.cg.oomKills()
	}
	sd.mu.Lock()
	seedGone := sd.dead || sd.deleting
	sd.mu.Unlock()
	switch {
	case killed:
		exit.Reason = killedFor
		if _, d := c.killRequest(); exit.Detail == "" {
			exit.Detail = d
		}
	case seedGone:
		exit.Reason = ReasonSeedGone
	case haveWait && result.err == nil && result.ws.Exited:
		exit.Reason = ReasonExited
		code := result.ws.ExitCode
		exit.ExitCode = &code
	case haveWait && result.err == nil:
		exit.Reason = ReasonKilled
		exit.Signal = result.ws.Signal
	case exit.OOMKills > 0:
		exit.Reason = ReasonOOM
	default:
		exit.Reason = ReasonKilled
		if haveWait && result.err != nil {
			exit.Detail = result.err.Error()
		}
	}

	c.mu.Lock()
	c.exit = exit
	c.mu.Unlock()
	close(c.done)

	// The caller has its answer. Release the host resources now.
	c.cleanup()
	close(c.cleaned)
}

// removeChild kills a child if it runs, waits until its host resources are
// gone and removes its record and files.
func (s *Server) removeChild(c *child) {
	c.setKill(ReasonDeleted, "deleted by request")
	select {
	case <-c.cleaned:
	case <-time.After(15 * time.Second):
	}
	s.mu.Lock()
	delete(s.children, c.id)
	s.mu.Unlock()
	if sd, oe := s.getSeed(c.seedID); oe == nil {
		sd.mu.Lock()
		delete(sd.children, c.id)
		sd.mu.Unlock()
	}
	os.RemoveAll(c.dir)
}

func (s *Server) deleteChild(id string) *opError {
	s.mu.Lock()
	c, ok := s.children[id]
	s.mu.Unlock()
	if !ok {
		return errf(CodeNotFound, "child %q not found", id)
	}
	s.removeChild(c)
	return nil
}

func (s *Server) doWait(req *WaitRequest) (*ChildInfo, *opError) {
	if req == nil {
		return nil, errf(CodeInvalidArgument, "wait request is missing")
	}
	s.mu.Lock()
	c, ok := s.children[req.ChildID]
	s.mu.Unlock()
	if !ok {
		return nil, errf(CodeNotFound, "child %q not found", req.ChildID)
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if req.TimeoutMS < 0 || timeout > time.Hour {
		timeout = time.Hour
	}
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-c.done:
		case <-t.C:
		}
	}
	info := c.snapshot()
	return &info, nil
}

func (s *Server) doList() ([]SeedInfo, []ChildInfo) {
	s.mu.Lock()
	var seeds []*seed
	for _, sd := range s.seeds {
		seeds = append(seeds, sd)
	}
	var kids []*child
	for _, c := range s.children {
		kids = append(kids, c)
	}
	s.mu.Unlock()
	var si []SeedInfo
	for _, sd := range seeds {
		si = append(si, sd.snapshot())
	}
	var ci []ChildInfo
	for _, c := range kids {
		ci = append(ci, c.snapshot())
	}
	return si, ci
}
