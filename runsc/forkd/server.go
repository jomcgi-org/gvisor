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
	"regexp"
	"strings"
	"sync"
	"time"
)

// Options configure a Server.
type Options struct {
	// StateDir holds the socket, one directory per seed and one per child. It
	// must be private to forkd.
	StateDir string
	// Settings are checked at startup (invariant I1).
	Settings Settings

	// AllowUnlimitedChildren lets a fork request omit its cgroup.
	AllowUnlimitedChildren bool
	// MaxChildren bounds the running children. Zero means 256.
	MaxChildren int
	// MaxRecords bounds children, running or exited, that a caller has not
	// deleted. Zero means 4096.
	MaxRecords int
	// DefaultMaxLifetime and DefaultLogBytesLimit apply to a fork request that
	// sets none. Zero means 10 minutes and 1 MiB.
	DefaultMaxLifetime   time.Duration
	DefaultLogBytesLimit int64
	// MaxEnvEntries and MaxEnvBytes bound a fork request's environment. Zero
	// means 32 entries and 4096 bytes.
	MaxEnvEntries int
	MaxEnvBytes   int
	// EnvPrefixes, if not empty, restrict fork environment names to those that
	// start with one of them, for example "ATE_ACTOR_".
	EnvPrefixes []string

	// skipStartupAssertions and skipAttestation exist for the tests of the server
	// logic, which run against a fake runtime without KVM. They are unexported:
	// forkd's main cannot set them.
	skipStartupAssertions bool
	skipAttestation       bool

	// AllowedUIDs may connect to the socket. Empty means forkd's own user.
	AllowedUIDs []uint32

	// Version, RunscSHA256 and SentrySHA256 are reported by hello.
	Version      string
	RunscSHA256  string
	SentrySHA256 string
}

func (o *Options) withDefaults() {
	if o.MaxChildren == 0 {
		o.MaxChildren = 256
	}
	if o.MaxRecords == 0 {
		o.MaxRecords = 4096
	}
	if o.DefaultMaxLifetime == 0 {
		o.DefaultMaxLifetime = 10 * time.Minute
	}
	if o.DefaultLogBytesLimit == 0 {
		o.DefaultLogBytesLimit = 1 << 20
	}
	if o.MaxEnvEntries == 0 {
		o.MaxEnvEntries = 32
	}
	if o.MaxEnvBytes == 0 {
		o.MaxEnvBytes = 4096
	}
	if len(o.AllowedUIDs) == 0 {
		o.AllowedUIDs = []uint32{uint32(os.Getuid())}
	}
}

// Server holds the seeds and children of one forkd.
type Server struct {
	opt        Options
	rt         Runtime
	cg         *cgroupParent
	assertions []Assertion

	mu       sync.Mutex
	seeds    map[string]*seed
	children map[string]*child
	closed   bool

	conns sync.WaitGroup
	lis   *listener
}

// NewServer runs the startup assertions and prepares the state directory. It
// returns an error naming every failed assertion and does not touch the runtime
// then.
func NewServer(opt Options, rt Runtime) (*Server, error) {
	opt.withDefaults()
	if opt.StateDir == "" || !filepath.IsAbs(opt.StateDir) {
		return nil, fmt.Errorf("state directory %q must be an absolute path", opt.StateDir)
	}
	opt.Settings.AllowNoCgroup = opt.AllowUnlimitedChildren
	opt.Settings.Platform = rt.Platform()
	assertions := checkStartup(opt.Settings)
	if opt.skipStartupAssertions {
		assertions = nil
	}
	if failed := failedAssertions(assertions); len(failed) > 0 {
		return nil, fmt.Errorf("startup assertions failed: %s", strings.Join(failed, "; "))
	}
	s := &Server{
		opt:        opt,
		rt:         rt,
		assertions: assertions,
		seeds:      make(map[string]*seed),
		children:   make(map[string]*child),
	}
	if opt.Settings.CgroupParentDir != "" {
		cg, err := checkCgroupParent(opt.Settings.CgroupParentDir)
		if err != nil {
			return nil, err
		}
		s.cg = cg
	}
	if err := os.MkdirAll(opt.StateDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(opt.StateDir, 0700); err != nil {
		return nil, err
	}
	// Whatever an earlier forkd left cannot be adopted: its seeds and children
	// are separate processes that this one has no handle on.
	if err := rt.Reset(); err != nil {
		return nil, fmt.Errorf("removing leftovers of an earlier forkd: %w", err)
	}
	removeStaleVeths()
	s.sweepCgroups()
	for _, sub := range []string{"seeds", "children"} {
		if err := os.RemoveAll(filepath.Join(opt.StateDir, sub)); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Join(opt.StateDir, sub), 0700); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// sweepCgroups removes leaves that an earlier forkd left below the parent.
func (s *Server) sweepCgroups() {
	if s.cg == nil {
		return
	}
	entries, err := os.ReadDir(s.cg.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			(&childCgroup{dir: filepath.Join(s.cg.dir, e.Name())}).remove()
		}
	}
}

// Assertions returns the results of the startup assertions.
func (s *Server) Assertions() []Assertion { return s.assertions }

func (s *Server) hello() *HelloInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	running := 0
	for _, c := range s.children {
		if c.running() {
			running++
		}
	}
	return &HelloInfo{
		ForkdVersion:    s.opt.Version,
		ProtocolVersion: ProtocolVersion,
		Platform:        s.rt.Platform(),
		RunscSHA256:     s.opt.RunscSHA256,
		SentrySHA256:    s.opt.SentrySHA256,
		Assertions:      s.assertions,
		MaxChildren:     s.opt.MaxChildren,
		Seeds:           len(s.seeds),
		Children:        running,
	}
}

// opError is an error with a protocol code.
type opError struct {
	code, msg string
}

func (e *opError) Error() string { return e.code + ": " + e.msg }

func errf(code, format string, args ...any) *opError {
	return &opError{code: code, msg: fmt.Sprintf(format, args...)}
}

var (
	envNameRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// Mount paths of the guest.
	guestPathRegexp = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)
)

// validateEnv checks entries that the child parses before its filter is on.
func (s *Server) validateEnv(env []string) error {
	if len(env) > s.opt.MaxEnvEntries {
		return fmt.Errorf("%d environment entries, at most %d", len(env), s.opt.MaxEnvEntries)
	}
	total := 0
	seen := map[string]bool{}
	for _, e := range env {
		name, _, ok := strings.Cut(e, "=")
		if !ok || !envNameRegexp.MatchString(name) {
			return fmt.Errorf("environment entry %.40q is not NAME=VALUE", e)
		}
		if strings.ContainsRune(e, 0) {
			return fmt.Errorf("environment entry %q contains a NUL byte", name)
		}
		if seen[name] {
			return fmt.Errorf("environment variable %q appears twice", name)
		}
		seen[name] = true
		if len(s.opt.EnvPrefixes) > 0 {
			allowed := false
			for _, p := range s.opt.EnvPrefixes {
				if strings.HasPrefix(name, p) {
					allowed = true
				}
			}
			if !allowed {
				return fmt.Errorf("environment variable %q does not start with an allowed prefix %v", name, s.opt.EnvPrefixes)
			}
		}
		total += len(e) + 1
	}
	if total > s.opt.MaxEnvBytes {
		return fmt.Errorf("environment is %d bytes, at most %d", total, s.opt.MaxEnvBytes)
	}
	return nil
}

// Close deletes every seed and child and stops serving.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	lis := s.lis
	var ids []string
	for id := range s.seeds {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	if lis != nil {
		lis.close()
	}
	for _, id := range ids {
		_ = s.deleteSeed(id)
	}
	s.conns.Wait()
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
