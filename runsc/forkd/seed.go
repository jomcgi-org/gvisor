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
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// seed is a booted template.
type seed struct {
	id   string
	dir  string
	tmpl Template
	// image stays open: the template boots from /proc/self/fd/N, the inode that
	// was hashed.
	image *os.File

	// cg is the seed's cgroup leaf, nil without a cgroup parent.
	cg *childCgroup

	mu       sync.Mutex
	info     SeedInfo
	creating bool
	// dead is set when the template process ended without a delete.
	dead     bool
	deleting bool
	children map[string]*child
	stdout   *os.File
	stderr   *os.File
}

func (sd *seed) snapshot() SeedInfo {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	info := sd.info
	info.Children = len(sd.children)
	if sd.cg != nil {
		info.OOMKills = sd.cg.oomKills()
	}
	if sd.dead {
		info.State = "dead"
	}
	return info
}

func (s *Server) validateSeed(req *SeedRequest) *opError {
	if req == nil {
		return errf(CodeInvalidArgument, "seed request is missing")
	}
	if err := ValidID(req.SeedID); err != nil {
		return errf(CodeInvalidArgument, "%v", err)
	}
	if req.Image == "" || !filepath.IsAbs(req.Image) {
		return errf(CodeInvalidArgument, "image must be an absolute path")
	}
	if !validSHA256(strings.ToLower(req.ImageSHA256)) {
		return errf(CodeInvalidArgument, "image_sha256 must be 64 hex digits: every seed image is pinned by digest")
	}
	if len(req.Args) == 0 || req.Args[0] == "" {
		return errf(CodeInvalidArgument, "args must not be empty")
	}
	if req.Cwd != "" && !strings.HasPrefix(req.Cwd, "/") {
		return errf(CodeInvalidArgument, "cwd %q must be absolute", req.Cwd)
	}
	for _, e := range req.Env {
		if name, _, ok := strings.Cut(e, "="); !ok || !envNameRegexp.MatchString(name) {
			return errf(CodeInvalidArgument, "environment entry %.40q is not NAME=VALUE", e)
		}
	}
	if req.Workers < 0 || req.Workers > 16 {
		return errf(CodeInvalidArgument, "workers must be between 0 and 16")
	}
	if req.CPUs < 0 || req.CPUs > 64 {
		return errf(CodeInvalidArgument, "cpus must be between 0 and 64")
	}
	// Without a cgroup parent there is nothing to limit with. Startup already
	// refused that unless unlimited children are allowed.
	if err := req.Cgroup.validateSeed(s.cg != nil && !s.opt.AllowUnlimitedChildren); err != nil {
		return errf(CodeInvalidArgument, "cgroup: %v", err)
	}
	if req.Cgroup != nil && s.cg == nil {
		return errf(CodeFailedPrecondition, "cgroup limits need forkd to run with --cgroup-parent")
	}
	seen := map[string]bool{}
	for _, t := range req.Tmpfs {
		if !guestPathRegexp.MatchString(t.Path) || t.Path == "/" || strings.Contains(t.Path, "..") {
			return errf(CodeInvalidArgument, "tmpfs path %q is not a safe absolute path", t.Path)
		}
		if seen[t.Path] {
			return errf(CodeInvalidArgument, "tmpfs path %q appears twice", t.Path)
		}
		seen[t.Path] = true
	}
	return nil
}

// doSeed boots a template. It holds no lock while it boots.
func (s *Server) doSeed(req *SeedRequest) (*SeedInfo, *opError) {
	if oe := s.validateSeed(req); oe != nil {
		return nil, oe
	}
	sd := &seed{id: req.SeedID, creating: true, children: map[string]*child{}}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errf(CodeUnavailable, "forkd is shutting down")
	}
	if _, dup := s.seeds[req.SeedID]; dup {
		s.mu.Unlock()
		return nil, errf(CodeAlreadyExists, "seed %q exists", req.SeedID)
	}
	s.seeds[req.SeedID] = sd
	s.mu.Unlock()

	fail := func(oe *opError) (*SeedInfo, *opError) {
		sd.release()
		s.mu.Lock()
		delete(s.seeds, req.SeedID)
		s.mu.Unlock()
		return nil, oe
	}

	// I7: the image must be the one the caller pinned. Hash the inode that the
	// template will boot from.
	f, digest, err := openImage(req.Image)
	if err != nil {
		return fail(errf(CodeFailedPrecondition, "%v", err))
	}
	sd.image = f
	if want := strings.ToLower(req.ImageSHA256); digest != want {
		return fail(errf(CodePermissionDenied, "image %q has SHA-256 %s, the request pins %s", req.Image, digest, want))
	}

	sd.dir = filepath.Join(s.opt.StateDir, "seeds", req.SeedID)
	if err := os.MkdirAll(sd.dir, 0700); err != nil {
		return fail(errf(CodeInternal, "%v", err))
	}
	open := func(name string) (*os.File, error) {
		return os.OpenFile(filepath.Join(sd.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	}
	if sd.stdout, err = open("template.stdout"); err != nil {
		return fail(errf(CodeInternal, "%v", err))
	}
	if sd.stderr, err = open("template.stderr"); err != nil {
		return fail(errf(CodeInternal, "%v", err))
	}

	// The leaf exists, with its limits, before the template boots: runsc puts
	// the template's processes into it when it creates them.
	cgroupPath := ""
	if s.cg != nil {
		if sd.cg, err = s.cg.createSeed(req.SeedID, req.Cgroup); err != nil {
			return fail(errf(CodeInternal, "%v", err))
		}
		cgroupPath = sd.cg.relative()
	}

	workers, cpus := req.Workers, req.CPUs
	if workers == 0 {
		workers = 1
	}
	if cpus == 0 {
		cpus = 1
	}
	start := time.Now()
	tmpl, err := s.rt.CreateTemplate(TemplateSpec{
		ID:               req.SeedID,
		Dir:              sd.dir,
		ImagePath:        fmt.Sprintf("/proc/self/fd/%d", sd.image.Fd()),
		CgroupPath:       cgroupPath,
		Args:             req.Args,
		Env:              req.Env,
		Cwd:              req.Cwd,
		UID:              req.UID,
		GID:              req.GID,
		DropCapabilities: req.DropCapabilities,
		Tmpfs:            req.Tmpfs,
		Workers:          workers,
		CPUs:             cpus,
		Stdout:           sd.stdout,
		Stderr:           sd.stderr,
	})
	if err != nil {
		return fail(errf(CodeInternal, "creating the template: %v", err))
	}
	sd.tmpl = tmpl
	ready := time.Since(start)

	var attestation []string
	if !s.opt.skipAttestation {
		var aerr error
		attestation, aerr = attestSeed(tmpl.PID(), sd.cg)
		if aerr != nil {
			_ = tmpl.Destroy()
			return fail(errf(CodeFailedPrecondition, "%v", aerr))
		}
	}

	sd.mu.Lock()
	sd.creating = false
	sd.info = SeedInfo{
		SeedID:      req.SeedID,
		State:       StateReady,
		PID:         tmpl.PID(),
		ImageSHA256: digest,
		Workers:     workers,
		CPUs:        cpus,
		Platform:    s.rt.Platform(),
		ReadyMS:     ready.Milliseconds(),
		CreatedUnix: time.Now().UnixMilli(),
		Attestation: attestation,
	}
	if sd.cg != nil {
		sd.info.CgroupPath = sd.cg.dir
	}
	sd.mu.Unlock()
	go s.watchSeed(sd)
	info := sd.snapshot()
	return &info, nil
}

// release closes what a seed holds besides the template.
func (sd *seed) release() {
	for _, f := range []*os.File{sd.stdout, sd.stderr, sd.image} {
		if f != nil {
			f.Close()
		}
	}
	sd.cg.remove()
	if sd.dir != "" {
		os.RemoveAll(sd.dir)
	}
}

// watchSeed notices that the template process ended on its own. Its children
// die with it: a template worker that exits ends the pool.
func (s *Server) watchSeed(sd *seed) {
	fd, err := unix.PidfdOpen(sd.tmpl.PID(), 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 500)
		if err == unix.EINTR {
			continue
		}
		sd.mu.Lock()
		deleting := sd.deleting
		sd.mu.Unlock()
		if deleting {
			return
		}
		if err == nil && n > 0 {
			sd.mu.Lock()
			sd.dead = true
			sd.mu.Unlock()
			return
		}
	}
}

func (s *Server) getSeed(id string) (*seed, *opError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sd, ok := s.seeds[id]
	if !ok {
		return nil, errf(CodeNotFound, "seed %q not found", id)
	}
	return sd, nil
}

// deleteSeed kills the seed's children, destroys the template and removes the
// seed.
func (s *Server) deleteSeed(id string) *opError {
	sd, oe := s.getSeed(id)
	if oe != nil {
		return oe
	}
	sd.mu.Lock()
	if sd.creating {
		sd.mu.Unlock()
		return errf(CodeFailedPrecondition, "seed %q is still starting", id)
	}
	if sd.deleting {
		sd.mu.Unlock()
		return errf(CodeFailedPrecondition, "seed %q is already being deleted", id)
	}
	sd.deleting = true
	var kids []*child
	for _, c := range sd.children {
		kids = append(kids, c)
	}
	sd.mu.Unlock()

	for _, c := range kids {
		c.setKill(ReasonSeedGone, "the seed was deleted")
	}
	var wg sync.WaitGroup
	for _, c := range kids {
		wg.Add(1)
		go func(c *child) {
			defer wg.Done()
			s.removeChild(c)
		}(c)
	}
	wg.Wait()
	if err := sd.tmpl.Destroy(); err != nil {
		// The state is gone from forkd's table either way; report what happened.
		s.mu.Lock()
		delete(s.seeds, id)
		s.mu.Unlock()
		sd.release()
		return errf(CodeInternal, "destroying the template: %v", err)
	}
	sd.release()
	s.mu.Lock()
	delete(s.seeds, id)
	s.mu.Unlock()
	return nil
}
