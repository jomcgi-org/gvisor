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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	in := Request{Version: ProtocolVersion, ID: "a", Op: OpFork, Fork: &ForkRequest{SeedID: "s", ChildID: "c", Env: []string{"A=1"}}}
	if err := WriteMessage(&buf, &in); err != nil {
		t.Fatal(err)
	}
	var out Request
	if err := ReadMessage(&buf, &out); err != nil {
		t.Fatal(err)
	}
	if out.Fork == nil || out.Fork.ChildID != "c" || out.Op != OpFork {
		t.Errorf("round trip = %+v", out)
	}
	// A frame ends cleanly with EOF, and a cut frame does not.
	if err := ReadMessage(&buf, &out); !errors.Is(err, os.ErrClosed) && err.Error() != "EOF" {
		t.Errorf("ReadMessage at the end = %v, want EOF", err)
	}
	cut := bytes.NewReader([]byte{0, 0, 0, 9, '{'})
	if err := ReadMessage(cut, &out); err == nil || err.Error() != "unexpected EOF" {
		t.Errorf("ReadMessage of a cut frame = %v, want unexpected EOF", err)
	}
	huge := bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})
	if err := ReadMessage(huge, &out); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("ReadMessage of a huge frame = %v, want a size error", err)
	}
	// Unknown fields are ignored, so that a newer peer can add optional ones.
	data := []byte(`{"version":1,"op":"list","future_field":{"x":1}}`)
	frame := append([]byte{0, 0, 0, byte(len(data))}, data...)
	var req Request
	if err := ReadMessage(bytes.NewReader(frame), &req); err != nil || req.Op != OpList {
		t.Errorf("ReadMessage with an unknown field = %+v, %v", req, err)
	}
}

func TestValidID(t *testing.T) {
	for _, id := range []string{"a", "child-1", "9f1c.x_y", strings.Repeat("a", 63)} {
		if err := ValidID(id); err != nil {
			t.Errorf("ValidID(%q) = %v", id, err)
		}
	}
	for _, id := range []string{"", "-a", "a/b", "../x", "a b", "a\x00", strings.Repeat("a", 64), ".hidden"} {
		if ValidID(id) == nil {
			t.Errorf("ValidID(%q) accepted an unsafe name", id)
		}
	}
}

// goodSettings pass every assertion that does not depend on the host.
func goodSettings() Settings {
	return Settings{
		Platform:       "kvm",
		Network:        "sandbox",
		ForkNamespaces: []string{"ipc", "net"},
		AllowNoCgroup:  true,
	}
}

func TestStartupAssertionsRefuse(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Settings)
		failed string
	}{
		{"test only mode", func(s *Settings) { s.TestOnlyUnsafe = true }, "production_mode"},
		{"seccomp off", func(s *Settings) { s.DisableSeccomp = true }, "sentry_seccomp"},
		{"rootless", func(s *Settings) { s.Rootless = true }, "not_rootless"},
		{"directfs", func(s *Settings) { s.DirectFS = true }, "no_directfs"},
		{"systrap", func(s *Settings) { s.Platform = "systrap" }, "platform_kvm"},
		{"host network", func(s *Settings) { s.Network = "host" }, "network_mode"},
		{"debug log", func(s *Settings) { s.Debug = true }, "no_shared_log_files"},
		{"debug log file", func(s *Settings) { s.DebugLog = "/tmp/x.log" }, "no_shared_log_files"},
		{"no ipc namespace", func(s *Settings) { s.ForkNamespaces = []string{"net"} }, "fork_namespaces"},
		{"no net namespace", func(s *Settings) { s.ForkNamespaces = nil }, "fork_namespaces"},
		{"no kvm", func(s *Settings) { s.KVMDevicePath = "/nonexistent/kvm" }, "kvm_present"},
		{"no cgroup", func(s *Settings) { s.AllowNoCgroup = false }, "cgroup_parent"},
		{"bad cgroup parent", func(s *Settings) { s.CgroupParentDir = "/tmp" }, "cgroup_parent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := goodSettings()
			tc.mutate(&s)
			for _, a := range checkStartup(s) {
				if a.Name == tc.failed {
					if a.OK {
						t.Errorf("assertion %s passed, want it to fail: %s", a.Name, a.Detail)
					}
					return
				}
			}
			t.Errorf("no assertion named %s", tc.failed)
		})
	}

	// NewServer refuses and names the assertion, before it touches the runtime.
	rt := &fakeRuntime{}
	s := goodSettings()
	s.TestOnlyUnsafe = true
	_, err := NewServer(Options{StateDir: t.TempDir(), Settings: s}, rt)
	if err == nil || !strings.Contains(err.Error(), "production_mode") {
		t.Errorf("NewServer with test-only settings = %v, want a production_mode error", err)
	}
	if rt.resets != 0 {
		t.Error("NewServer touched the runtime after a failed assertion")
	}
}

func TestStartupAssertionsPassOnThisHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("needs /dev/kvm")
	}
	st, err := readProcStatus(os.Getpid())
	if err != nil || st.CapEff&capBit(capSysAdmin) == 0 {
		t.Skip("needs CAP_SYS_ADMIN")
	}
	s := goodSettings()
	s.Network = "none" // CAP_NET_ADMIN is not needed then
	for _, a := range checkStartup(s) {
		if !a.OK && a.Name != "capabilities" {
			t.Errorf("assertion %s failed: %s", a.Name, a.Detail)
		}
	}
}

func TestParseProcStatus(t *testing.T) {
	st, err := parseProcStatus("Name:\tx\nPPid:\t7\nNoNewPrivs:\t1\nSeccomp:\t2\nCapPrm:\t0000000000200000\nCapEff:\t0000000000200000\nCapBnd:\t000001ffffffffff\n")
	if err != nil {
		t.Fatal(err)
	}
	if st.PPid != 7 || st.NoNewPrivs != 1 || st.Seccomp != 2 || st.CapEff != 0x200000 || st.CapBnd != 0x1ffffffffff {
		t.Errorf("parseProcStatus = %+v", st)
	}
	if _, err := parseProcStatus("Name:\tx\n"); err == nil {
		t.Error("parseProcStatus accepted a status without the fields")
	}
}

func TestAttestRefusesUnconfinedProcesses(t *testing.T) {
	// The test process has no seccomp filter set by forkd and shares every
	// namespace with its parent: it is not a conforming child.
	if _, err := attestChild(os.Getpid()); err == nil {
		t.Error("attestChild accepted the test process")
	} else if !strings.Contains(err.Error(), "namespace") {
		t.Errorf("attestChild = %v, want a namespace complaint among the failures", err)
	}
	// A seed process with capabilities besides CAP_SYS_ADMIN is refused, but
	// only when the test runs with some.
	if st, err := readProcStatus(os.Getpid()); err == nil && (st.CapEff|st.CapPrm|st.CapAmb)&^capBit(capSysAdmin) != 0 {
		if _, err := attestSeed(os.Getpid(), nil); err == nil {
			t.Error("attestSeed accepted a process with extra capabilities")
		}
	}
}

func writeImage(t *testing.T, dir, content string, mode os.FileMode) (path, digest string) {
	t.Helper()
	path = filepath.Join(dir, "image.erofs")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func TestOpenImage(t *testing.T) {
	dir := t.TempDir()
	path, digest := writeImage(t, dir, "image bytes", 0444)
	f, got, err := openImage(path)
	if err != nil || got != digest {
		t.Fatalf("openImage = %q, %v, want %s", got, err, digest)
	}
	f.Close()
	if _, _, err := openImage("relative"); err == nil {
		t.Error("openImage accepted a relative path")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openImage(link); err == nil {
		t.Error("openImage followed a symlink")
	}
	writable, _ := writeImage(t, t.TempDir(), "x", 0666)
	if _, _, err := openImage(writable); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("openImage of a group-writable file = %v, want a writable error", err)
	}
	if _, _, err := openImage(dir); err == nil {
		t.Error("openImage accepted a directory")
	}
}

// testEnv is a server on a socket with a fake runtime.
type testEnv struct {
	t      *testing.T
	srv    *Server
	rt     *fakeRuntime
	sock   string
	client *Client
	dir    string
}

func newEnv(t *testing.T, mutate func(*Options)) *testEnv {
	t.Helper()
	dir, err := os.MkdirTemp("", "fd")
	if err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{}
	opt := Options{
		StateDir:               filepath.Join(dir, "state"),
		AllowUnlimitedChildren: true,
		skipStartupAssertions:  true,
		skipAttestation:        true,
	}
	if mutate != nil {
		mutate(&opt)
	}
	srv, err := NewServer(opt, rt)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s.sock")
	if err := srv.Listen(sock); err != nil {
		t.Fatal(err)
	}
	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{t: t, srv: srv, rt: rt, sock: sock, client: c, dir: dir}
	t.Cleanup(func() {
		c.Close()
		srv.Close()
		os.RemoveAll(dir)
	})
	return e
}

func (e *testEnv) seed(id string) *SeedInfo {
	e.t.Helper()
	path, digest := writeImage(e.t, e.dir, "rootfs "+id, 0444)
	req := &SeedRequest{SeedID: id, Image: path, ImageSHA256: digest, Args: []string{"/app"}, Tmpfs: []Tmpfs{{Path: "/tmp", SizeBytes: 1 << 20}}}
	if e.srv.cg != nil {
		req.Cgroup = &Cgroup{MemoryMax: 256 << 20}
	}
	info, err := e.client.Seed(req)
	if err != nil {
		e.t.Fatalf("Seed: %v", err)
	}
	return info
}

func (e *testEnv) fork(seed, id string, env ...string) *ChildInfo {
	e.t.Helper()
	info, err := e.client.Fork(&ForkRequest{SeedID: seed, ChildID: id, Env: env})
	if err != nil {
		e.t.Fatalf("Fork %s: %v", id, err)
	}
	return info
}

func codeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprint(err)
}

func processGone(pid int) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := unix.Kill(pid, 0); err == unix.ESRCH {
			return true
		}
		// A zombie that nobody reaped counts as gone: read its state.
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil && strings.Contains(string(data), ") Z ") {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestHelloSeedListDelete(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.Version = "test" })
	if e.rt.resets != 1 {
		t.Errorf("runtime reset %d times at startup, want 1", e.rt.resets)
	}
	h, err := e.client.Hello()
	if err != nil || h.ProtocolVersion != ProtocolVersion || h.ForkdVersion != "test" || h.Platform != "kvm" {
		t.Fatalf("Hello = %+v, %v", h, err)
	}
	info := e.seed("s1")
	if info.State != StateReady || info.PID == 0 || info.Workers != 1 || info.CPUs != 1 {
		t.Errorf("Seed = %+v", info)
	}
	if _, err := e.client.Seed(&SeedRequest{SeedID: "s1"}); codeOf(err) != CodeInvalidArgument && codeOf(err) != CodeAlreadyExists {
		t.Errorf("second Seed = %v, want an error", err)
	}
	seeds, kids, err := e.client.List()
	if err != nil || len(seeds) != 1 || len(kids) != 0 {
		t.Fatalf("List = %v %v %v", seeds, kids, err)
	}
	if err := e.client.DeleteSeed("s1"); err != nil {
		t.Fatal(err)
	}
	if !processGone(info.PID) {
		t.Error("the template process still runs after DeleteSeed")
	}
	if seeds, _, _ := e.client.List(); len(seeds) != 0 {
		t.Errorf("List after DeleteSeed = %v", seeds)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "state", "seeds", "s1")); !os.IsNotExist(err) {
		t.Errorf("seed directory remains: %v", err)
	}
	if err := e.client.DeleteSeed("s1"); codeOf(err) != CodeNotFound {
		t.Errorf("DeleteSeed of a deleted seed = %v, want not_found", err)
	}
}

func TestSeedPinsTheImageDigest(t *testing.T) {
	e := newEnv(t, nil)
	path, digest := writeImage(t, e.dir, "golden", 0444)
	other := strings.Repeat("0", 64)
	if _, err := e.client.Seed(&SeedRequest{SeedID: "s", Image: path, ImageSHA256: other, Args: []string{"/a"}}); codeOf(err) != CodePermissionDenied {
		t.Errorf("Seed with the wrong digest = %v, want permission_denied", err)
	}
	if len(e.rt.templates) != 0 {
		t.Error("a template booted from an image whose digest does not match")
	}
	if _, err := e.client.Seed(&SeedRequest{SeedID: "s", Image: path, Args: []string{"/a"}}); codeOf(err) != CodeInvalidArgument {
		t.Errorf("Seed without a digest = %v, want invalid_argument", err)
	}
	// After a refusal the ID is free again, and the right digest boots.
	if _, err := e.client.Seed(&SeedRequest{SeedID: "s", Image: path, ImageSHA256: strings.ToUpper(digest), Args: []string{"/a"}}); err != nil {
		t.Errorf("Seed with the right digest = %v", err)
	}
}

func TestSeedRejectsBadRequests(t *testing.T) {
	e := newEnv(t, nil)
	path, digest := writeImage(t, e.dir, "g", 0444)
	good := SeedRequest{SeedID: "s", Image: path, ImageSHA256: digest, Args: []string{"/a"}}
	for name, mutate := range map[string]func(*SeedRequest){
		"bad id":       func(r *SeedRequest) { r.SeedID = "../x" },
		"no args":      func(r *SeedRequest) { r.Args = nil },
		"rel image":    func(r *SeedRequest) { r.Image = "image" },
		"rel cwd":      func(r *SeedRequest) { r.Cwd = "work" },
		"bad env":      func(r *SeedRequest) { r.Env = []string{"nope"} },
		"workers":      func(r *SeedRequest) { r.Workers = 99 },
		"tmpfs root":   func(r *SeedRequest) { r.Tmpfs = []Tmpfs{{Path: "/"}} },
		"tmpfs dotdot": func(r *SeedRequest) { r.Tmpfs = []Tmpfs{{Path: "/a/../b"}} },
		"tmpfs twice":  func(r *SeedRequest) { r.Tmpfs = []Tmpfs{{Path: "/a"}, {Path: "/a"}} },
	} {
		req := good
		mutate(&req)
		if _, err := e.client.Seed(&req); codeOf(err) != CodeInvalidArgument {
			t.Errorf("%s: Seed = %v, want invalid_argument", name, err)
		}
	}
}

func TestForkEnvironmentRules(t *testing.T) {
	e := newEnv(t, func(o *Options) {
		o.EnvPrefixes = []string{"ATE_ACTOR_"}
		o.MaxEnvEntries = 3
		o.MaxEnvBytes = 100
	})
	e.seed("s")
	fork := func(env ...string) error {
		_, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: fmt.Sprintf("c%d", time.Now().UnixNano()), Env: env})
		return err
	}
	for name, env := range map[string][]string{
		"other name":   {"PATH=/bin"},
		"no equals":    {"ATE_ACTOR_X"},
		"bad name":     {"ATE_ACTOR_X-Y=1"},
		"duplicate":    {"ATE_ACTOR_A=1", "ATE_ACTOR_A=2"},
		"too many":     {"ATE_ACTOR_A=1", "ATE_ACTOR_B=1", "ATE_ACTOR_C=1", "ATE_ACTOR_D=1"},
		"too big":      {"ATE_ACTOR_A=" + strings.Repeat("x", 100)},
		"nul in value": {"ATE_ACTOR_A=a\x00b"},
	} {
		if err := fork(env...); codeOf(err) != CodeInvalidArgument {
			t.Errorf("%s: Fork = %v, want invalid_argument", name, err)
		}
	}
	if err := fork("ATE_ACTOR_NAME=a", "ATE_ACTOR_UID=b"); err != nil {
		t.Errorf("Fork with control-plane identity = %v", err)
	}
}

func TestForkLimitsAreRequired(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.AllowUnlimitedChildren = false })
	e.seed("s")
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "c"}); codeOf(err) != CodeInvalidArgument {
		t.Errorf("Fork without a cgroup = %v, want invalid_argument", err)
	}
	// Limits without a cgroup parent cannot be applied.
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "c", Cgroup: &Cgroup{PidsMax: 64, MemoryMax: 1 << 28}}); codeOf(err) != CodeFailedPrecondition {
		t.Errorf("Fork with limits but no cgroup parent = %v, want failed_precondition", err)
	}
	for name, cg := range map[string]*Cgroup{
		"no pids":        {MemoryMax: 1 << 28},
		"no memory":      {PidsMax: 64},
		"high only":      {PidsMax: 64, MemoryHigh: 1 << 20},
		"high above max": {PidsMax: 64, MemoryHigh: 2 << 20, MemoryMax: 1 << 20},
		"negative":       {PidsMax: -1, MemoryMax: 1},
		"bad cpu":        {PidsMax: 64, MemoryMax: 1 << 20, CPUMax: "fast"},
	} {
		if err := cg.validate(true); err == nil {
			t.Errorf("%s: validate accepted %+v", name, cg)
		}
	}
	if err := (&Cgroup{PidsMax: 64, MemoryHigh: 1 << 20, MemoryMax: 2 << 20, CPUMax: "50000 100000"}).validate(true); err != nil {
		t.Errorf("validate rejected good limits: %v", err)
	}
}

func TestSeedLimitsAreChecked(t *testing.T) {
	for name, cg := range map[string]*Cgroup{
		"no cgroup":      nil,
		"no memory":      {PidsMax: 64},
		"high only":      {MemoryHigh: 1 << 20},
		"high above max": {MemoryHigh: 2 << 20, MemoryMax: 1 << 20},
		"negative":       {MemoryMax: -1},
		"bad cpu":        {MemoryMax: 1 << 20, CPUMax: "fast"},
	} {
		if err := cg.validateSeed(true); err == nil {
			t.Errorf("%s: validateSeed accepted %+v", name, cg)
		}
	}
	// A seed needs no pids_max.
	if err := (&Cgroup{MemoryMax: 1 << 30}).validateSeed(true); err != nil {
		t.Errorf("validateSeed rejected a memory limit: %v", err)
	}
	if err := (*Cgroup)(nil).validateSeed(false); err != nil {
		t.Errorf("validateSeed(false) rejected no cgroup: %v", err)
	}
}

func TestChildExitIsWatched(t *testing.T) {
	e := newEnv(t, nil)
	e.seed("s")
	info := e.fork("s", "c1", "FAKE_SLEEP_MS=150", "FAKE_EXIT=3", "FAKE_WRITE=10")
	if info.State != StateRunning || info.PID == 0 || info.StdoutPath == "" {
		t.Fatalf("Fork = %+v", info)
	}
	// Polling returns the running state without blocking.
	if got, err := e.client.Wait("c1", 0); err != nil || got.State != StateRunning || got.Exit != nil {
		t.Errorf("Wait(0) = %+v, %v, want running", got, err)
	}
	got, err := e.client.Wait("c1", 10_000)
	if err != nil || got.State != StateExited {
		t.Fatalf("Wait = %+v, %v", got, err)
	}
	if got.Exit.Reason != ReasonExited || got.Exit.ExitCode == nil || *got.Exit.ExitCode != 3 {
		t.Errorf("exit = %+v, want exited with code 3", got.Exit)
	}
	out, err := os.ReadFile(info.StdoutPath)
	if err != nil || string(out) != "xxxxxxxxxx" {
		t.Errorf("stdout = %q, %v", out, err)
	}
	// The record stays until the caller deletes it; a second wait still answers.
	if again, err := e.client.Wait("c1", 0); err != nil || again.Exit == nil || again.Exit.Reason != ReasonExited {
		t.Errorf("second Wait = %+v, %v", again, err)
	}
	if err := e.client.DeleteChild("c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Wait("c1", 0); codeOf(err) != CodeNotFound {
		t.Errorf("Wait after delete = %v, want not_found", err)
	}
	if _, err := os.Stat(filepath.Dir(info.StdoutPath)); !os.IsNotExist(err) {
		t.Errorf("child directory remains: %v", err)
	}
}

func TestChildKillReasons(t *testing.T) {
	e := newEnv(t, nil)
	e.seed("s")

	// Deadline.
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "life", MaxLifetimeMS: 300}); err != nil {
		t.Fatal(err)
	}
	// Output cap.
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "logs", Env: []string{"FAKE_WRITE=100000"}, LogBytesLimit: 1000}); err != nil {
		t.Fatal(err)
	}
	// Killed from outside.
	ext := e.fork("s", "ext")
	if err := unix.Kill(ext.PID, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	// Deleted while it runs.
	run := e.fork("s", "run")

	want := map[string]string{"life": ReasonMaxLifetime, "logs": ReasonLogLimit, "ext": ReasonKilled}
	for id, reason := range want {
		got, err := e.client.Wait(id, 10_000)
		if err != nil || got.State != StateExited || got.Exit.Reason != reason {
			t.Errorf("%s: Wait = %+v %v, want reason %s", id, got, err, reason)
		}
	}
	if err := e.client.DeleteChild("run"); err != nil {
		t.Fatal(err)
	}
	if !processGone(run.PID) {
		t.Error("deleting a running child did not kill it")
	}
}

func TestDeleteSeedKillsChildren(t *testing.T) {
	e := newEnv(t, nil)
	e.seed("s")
	a, b := e.fork("s", "a"), e.fork("s", "b")
	if err := e.client.DeleteSeed("s"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*ChildInfo{a, b} {
		if !processGone(c.PID) {
			t.Errorf("child %s still runs after its seed was deleted", c.ChildID)
		}
	}
	if _, kids, _ := e.client.List(); len(kids) != 0 {
		t.Errorf("children remain after DeleteSeed: %+v", kids)
	}
}

func TestDeadSeedRefusesForks(t *testing.T) {
	e := newEnv(t, nil)
	info := e.seed("s")
	if err := unix.Kill(info.PID, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		seeds, _, _ := e.client.List()
		if len(seeds) == 1 && seeds[0].State == "dead" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the seed is not reported dead: %+v", seeds)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "c"}); codeOf(err) != CodeFailedPrecondition {
		t.Errorf("Fork from a dead seed = %v, want failed_precondition", err)
	}
	if err := e.client.DeleteSeed("s"); err != nil {
		t.Errorf("DeleteSeed of a dead seed = %v", err)
	}
}

func TestLimitsAndErrors(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxChildren = 2 })
	e.seed("s")
	e.fork("s", "a")
	e.fork("s", "b")
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "c"}); codeOf(err) != CodeResourceExhausted {
		t.Errorf("third Fork = %v, want resource_exhausted", err)
	}
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "a"}); codeOf(err) != CodeAlreadyExists {
		t.Errorf("Fork of an existing ID = %v, want already_exists", err)
	}
	if _, err := e.client.Fork(&ForkRequest{SeedID: "nope", ChildID: "d"}); codeOf(err) != CodeNotFound {
		t.Errorf("Fork from a missing seed = %v, want not_found", err)
	}
	if err := e.client.DeleteChild("nope"); codeOf(err) != CodeNotFound {
		t.Errorf("DeleteChild of a missing child = %v, want not_found", err)
	}
	if _, err := e.client.Do(&Request{Op: "frobnicate"}); codeOf(err) != CodeInvalidArgument {
		t.Errorf("unknown op = %v, want invalid_argument", err)
	}
	r, err := e.client.Do(&Request{Op: OpList})
	if err != nil || len(r.Children) != 2 {
		t.Errorf("List = %+v, %v", r, err)
	}
	// A failed fork leaves nothing behind.
	e.rt.failFork = fmt.Errorf("boom")
	e.client.DeleteChild("b")
	if _, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "f"}); codeOf(err) != CodeInternal {
		t.Errorf("failing Fork = %v, want internal", err)
	}
	if _, kids, _ := e.client.List(); len(kids) != 1 {
		t.Errorf("children after a failed fork = %+v, want only a", kids)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "state", "children", "f")); !os.IsNotExist(err) {
		t.Errorf("a failed fork left its directory: %v", err)
	}
}

func TestVersionMismatch(t *testing.T) {
	e := newEnv(t, nil)
	conn := e.client.conn
	if err := WriteMessage(conn, &Request{Version: 99, Op: OpHello}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := ReadMessage(conn, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Error == nil || resp.Error.Code != CodeInvalidArgument || !strings.Contains(resp.Error.Message, "99") {
		t.Errorf("response to version 99 = %+v", resp)
	}
}

func TestPeerCredentialsAreChecked(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.AllowedUIDs = []uint32{uint32(os.Getuid()) + 1} })
	c, err := Dial(e.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Hello(); err == nil {
		t.Error("forkd answered a user that is not allowed")
	}
	st, err := os.Stat(e.sock)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Errorf("socket mode = %v, %v, want 0600", st.Mode(), err)
	}
}

func cgroup2Writable(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupMount, &st); err != nil || st.Type != cgroup2Magic {
		t.Skip("needs cgroup v2")
	}
	dir := filepath.Join(cgroupMount, fmt.Sprintf("forkd-ut-%d", os.Getpid()))
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
	}
	t.Cleanup(func() { (&childCgroup{dir: dir}).remove() })
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+memory +pids"), 0644); err != nil {
		t.Skipf("cannot delegate memory and pids: %v", err)
	}
	// cpu is optional: a host may not offer it.
	_ = os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+cpu"), 0644)
	return dir
}

func TestChildCgroupLimits(t *testing.T) {
	parent := cgroup2Writable(t)
	e := newEnv(t, func(o *Options) {
		o.AllowUnlimitedChildren = false
		o.Settings.CgroupParentDir = parent
	})
	e.seed("s")
	cpu := "50000 100000"
	if data, _ := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control")); !strings.Contains(string(data), "cpu") {
		cpu = ""
	}
	info, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "limited", MaxLifetimeMS: 60_000,
		Cgroup: &Cgroup{PidsMax: 77, MemoryHigh: 50 << 20, MemoryMax: 64 << 20, CPUMax: cpu}})
	if err != nil {
		t.Fatal(err)
	}
	if info.CgroupPath != filepath.Join(parent, "limited") {
		t.Fatalf("cgroup path = %q", info.CgroupPath)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(info.CgroupPath, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	wantFiles := map[string]string{
		"pids.max":        "77",
		"memory.high":     fmt.Sprint(50 << 20),
		"memory.max":      fmt.Sprint(64 << 20),
		"memory.swap.max": "0",
	}
	if cpu != "" {
		wantFiles["cpu.max"] = cpu
	}
	for name, want := range wantFiles {
		if got := read(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if procs := read("cgroup.procs"); procs != fmt.Sprint(info.PID) {
		t.Errorf("cgroup.procs = %q, want the child %d: the child must be in its cgroup", procs, info.PID)
	}
	if err := e.client.DeleteChild("limited"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(info.CgroupPath); !os.IsNotExist(err) {
		t.Errorf("the cgroup leaf remains after the child is deleted: %v", err)
	}
}

func TestSeedCgroupLimits(t *testing.T) {
	parent := cgroup2Writable(t)
	e := newEnv(t, func(o *Options) {
		o.AllowUnlimitedChildren = false
		o.Settings.CgroupParentDir = parent
	})
	path, digest := writeImage(t, e.dir, "rootfs seed", 0444)
	req := &SeedRequest{SeedID: "s", Image: path, ImageSHA256: digest, Args: []string{"/app"}}
	// The limit is required once forkd has a cgroup parent.
	if _, err := e.client.Seed(req); codeOf(err) != CodeInvalidArgument {
		t.Fatalf("Seed without a cgroup = %v, want invalid_argument", err)
	}
	req.Cgroup = &Cgroup{MemoryHigh: 100 << 20}
	if _, err := e.client.Seed(req); codeOf(err) != CodeInvalidArgument {
		t.Fatalf("Seed with memory_high only = %v, want invalid_argument", err)
	}
	req.Cgroup = &Cgroup{MemoryMax: 128 << 20, PidsMax: 200}
	info, err := e.client.Seed(req)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(parent, seedLeafPrefix+"s")
	if info.CgroupPath != want {
		t.Fatalf("seed cgroup path = %q, want %q", info.CgroupPath, want)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(want, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	for name, w := range map[string]string{"memory.max": fmt.Sprint(128 << 20), "pids.max": "200", "memory.swap.max": "0"} {
		if got := read(name); got != w {
			t.Errorf("%s = %q, want %q", name, got, w)
		}
	}
	if procs := read("cgroup.procs"); procs != fmt.Sprint(info.PID) {
		t.Errorf("cgroup.procs = %q, want the template %d", procs, info.PID)
	}
	// A child's own leaf is a sibling, never inside the seed's.
	child, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "c1", Cgroup: &Cgroup{PidsMax: 64, MemoryMax: 64 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(child.CgroupPath) != parent {
		t.Errorf("child cgroup %q is not a sibling of the seed's", child.CgroupPath)
	}
	// A second seed with the same id fails and leaves the first one's leaf.
	if _, err := e.client.Seed(req); codeOf(err) != CodeAlreadyExists {
		t.Errorf("duplicate Seed = %v, want already_exists", err)
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("the seed's leaf disappeared: %v", err)
	}
	if err := e.client.DeleteSeed("s"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Errorf("the seed's leaf remains after the seed is deleted: %v", err)
	}
	if _, err := os.Stat(child.CgroupPath); !os.IsNotExist(err) {
		t.Errorf("the child's leaf remains after its seed is deleted: %v", err)
	}
}

func TestStaleCgroupLeavesAreSweptAtStartup(t *testing.T) {
	parent := cgroup2Writable(t)
	stale := filepath.Join(parent, "stale-leaf")
	if err := os.Mkdir(stale, 0755); err != nil {
		t.Fatal(err)
	}
	newEnv(t, func(o *Options) { o.Settings.CgroupParentDir = parent })
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("a stale cgroup leaf survived startup: %v", err)
	}
}

func TestVethPerChild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	e := newEnv(t, nil)
	e.seed("s")
	info, err := e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "n1", Net: &Net{Veth: &Veth{HostCIDR: "198.18.77.1/30", GuestCIDR: "198.18.77.2/30"}}})
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("no CAP_NET_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	if !strings.HasPrefix(info.NetNSPath, "/proc/self/fd/") {
		t.Errorf("netns path = %q", info.NetNSPath)
	}
	fake := e.rt.templates[0].children[0]
	if fake.spec.NetNSPath != info.NetNSPath {
		t.Errorf("runtime got netns %q, want %q", fake.spec.NetNSPath, info.NetNSPath)
	}
	hostIf := func() bool {
		links, _ := os.ReadDir("/sys/class/net")
		for _, l := range links {
			if strings.HasPrefix(l.Name(), vethPrefix) {
				return true
			}
		}
		return false
	}
	if !hostIf() {
		t.Error("the host end of the veth pair is missing")
	}
	if err := e.client.DeleteChild("n1"); err != nil {
		t.Fatal(err)
	}
	if hostIf() {
		t.Error("the host end of the veth pair remains after the child is deleted")
	}
	// Exactly one of netns_path and veth.
	_, err = e.client.Fork(&ForkRequest{SeedID: "s", ChildID: "n2", Net: &Net{NetNSPath: "/proc/1/ns/net", Veth: &Veth{HostCIDR: "198.18.77.1/30", GuestCIDR: "198.18.77.2/30"}}})
	if codeOf(err) != CodeInvalidArgument {
		t.Errorf("Fork with both netns_path and veth = %v, want invalid_argument", err)
	}
}

// The bounding set is per thread. After DropForbiddenCapabilities no thread of
// the process may keep a forbidden capability, however the goroutines moved.
func TestDropForbiddenCapabilitiesReachesEveryThread(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	// Make threads: blocked goroutines each hold an OS thread.
	var wg, started sync.WaitGroup
	release := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		started.Add(1)
		go func() {
			runtime.LockOSThread()
			defer wg.Done()
			started.Done()
			<-release
		}()
	}
	started.Wait()
	defer func() { close(release); wg.Wait() }()
	if err := DropForbiddenCapabilities(); err != nil {
		t.Skipf("cannot drop capabilities: %v", err)
	}
	forbidden := capBit(capSysModule) | capBit(capSysRawio) | capBit(capSysBoot) | capBit(capSysTime) | capBit(capMacAdmin) | capBit(capMacOverride)
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) < 16 {
		t.Fatalf("only %d threads, the test needs many", len(tasks))
	}
	for _, task := range tasks {
		data, err := os.ReadFile("/proc/self/task/" + task.Name() + "/status")
		if err != nil {
			continue // exited meanwhile
		}
		st, err := parseProcStatus(string(data))
		if err != nil {
			t.Fatal(err)
		}
		if st.CapBnd&forbidden != 0 {
			t.Errorf("thread %s keeps %#x in its bounding set", task.Name(), st.CapBnd&forbidden)
		}
	}
}
