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

package forkd_test

// These tests run the forkd binary from the release layout (gvisor-bin/forkd)
// against real runsc on KVM, in production mode. They need root, /dev/kvm,
// cgroup v2, mkfs.erofs and a static busybox, and skip otherwise.
//
// TestForkdEngine also needs a digest-pinned EROFS image with a scan engine;
// set FORKD_ENGINE_IMAGE, FORKD_ENGINE_ARGS (space separated),
// FORKD_ENGINE_ENV (comma separated NAME=VALUE) and FORKD_ENGINE_TARGET.

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/forkd"
)

func needsHost(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("needs /dev/kvm")
	}
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil || st.Type != 0x63677270 {
		t.Skip("needs cgroup v2")
	}
	for _, tool := range []string{"mkfs.erofs", "busybox"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s: %v", tool, err)
		}
	}
}

func forkdBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("FORKD_BIN"); p != "" {
		return p
	}
	p, err := testutil.FindFile("release/gvisor-bin/forkd")
	if err != nil {
		t.Skipf("forkd is not in the release layout: %v", err)
	}
	return p
}

// guest is a busybox shell that initializes, asks for the fork checkpoint and
// then does what the child's spec environment says: CHILD_EXIT=<n> exits with
// n, CHILD_HOLD=1 sleeps, CHILD_LISTEN=1 serves TCP :8080 once,
// CHILD_ALLOC_MB=<n> writes n MB to /tmp.
const guest = `/busybox echo TEMPLATE_INITIALIZED
exec 3<>/proc/gvisor/checkpoint
echo 1 >&3
/busybox cat <&3 | /busybox grep -qx restore || exit 99
E=$(/busybox tr '\0' '\n' </proc/gvisor/spec_environ)
v() { echo "$E" | /busybox sed -n "s/^$1=//p"; }
/busybox echo READY
echo "$E"
[ -n "$(v CHILD_ALLOC_MB)" ] && /busybox dd if=/dev/zero of=/tmp/big bs=1M count=$(v CHILD_ALLOC_MB) 2>/dev/null
[ -n "$(v CHILD_LISTEN)" ] && /busybox nc -l -p 8080 -w 30 </dev/null >/dev/null
[ -n "$(v CHILD_HOLD)" ] && exec /busybox sleep 3600
X=$(v CHILD_EXIT)
exit ${X:-0}
`

// buildBusyboxImage returns the path and SHA-256 of a read-only EROFS image
// with a static busybox. The build is reproducible, so the digest is pinned
// like a production image.
func buildBusyboxImage(t *testing.T, dir string) (path, digest string) {
	t.Helper()
	root := filepath.Join(dir, "rootfs")
	for _, d := range []string{"", "dev", "proc", "sys", "tmp", "etc"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	bb, err := exec.LookPath("busybox")
	if err != nil {
		t.Fatal(err)
	}
	if err := testutil.Copy(bb, filepath.Join(root, "busybox")); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "busybox.erofs")
	out, err := exec.Command("mkfs.erofs", "-E", "noinline_data", "-T", "0", "-U", "00000000-0000-0000-0000-000000000001", path, root).CombinedOutput()
	if err != nil {
		t.Fatalf("mkfs.erofs: %v\n%s", err, out)
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	sum, err := exec.Command("sha256sum", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.Fields(string(sum))[0]
}

// cgroupParent makes a cgroup with the controllers delegated.
func cgroupParent(t *testing.T) string {
	t.Helper()
	dir := fmt.Sprintf("/sys/fs/cgroup/forkd-it-%d", os.Getpid())
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Skipf("cannot create a cgroup: %v", err)
	}
	t.Cleanup(func() { unix.Rmdir(dir) })
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+memory +pids"), 0644); err != nil {
		t.Skipf("cannot delegate memory and pids: %v", err)
	}
	_ = os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+cpu"), 0644)
	return dir
}

type daemon struct {
	t      *testing.T
	cmd    *exec.Cmd
	stderr *bytes.Buffer
	state  string
	sock   string
	parent string
}

func startForkd(t *testing.T, args ...string) *daemon {
	t.Helper()
	bin := forkdBinary(t)
	state, err := os.MkdirTemp("", "forkd-it")
	if err != nil {
		t.Fatal(err)
	}
	d := &daemon{t: t, state: state, sock: filepath.Join(state, "forkd.sock"), stderr: &bytes.Buffer{}, parent: cgroupParent(t)}
	d.cmd = exec.Command(bin, append([]string{"--forkd-state-dir=" + state, "--forkd-cgroup-parent=" + d.parent}, args...)...)
	d.cmd.Stderr = d.stderr
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = d.cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		d.cmd.Process.Signal(unix.SIGTERM)
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			d.cmd.Process.Kill()
			<-done
		}
		os.RemoveAll(state)
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case <-done:
			t.Fatalf("forkd exited: %v\n%s", waitErr, d.stderr.String())
		default:
		}
		if _, err := os.Stat(d.sock); err == nil {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("forkd did not listen:\n%s", d.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (d *daemon) dial() *forkd.Client {
	d.t.Helper()
	c, err := forkd.Dial(d.sock)
	if err != nil {
		d.t.Fatal(err)
	}
	d.t.Cleanup(func() { c.Close() })
	return c
}

var limits = &forkd.Cgroup{PidsMax: 64, MemoryHigh: 192 << 20, MemoryMax: 256 << 20}

// seedLimits is the cgroup of a seed. The guest sees its memory.max as its
// total memory.
var seedLimits = &forkd.Cgroup{MemoryMax: 1 << 30}

func seedBusybox(t *testing.T, c *forkd.Client, id string) *forkd.SeedInfo {
	t.Helper()
	image, digest := buildBusyboxImage(t, t.TempDir())
	info, err := c.Seed(&forkd.SeedRequest{
		SeedID: id, Image: image, ImageSHA256: digest,
		Args:   []string{"/busybox", "sh", "-c", guest},
		Env:    []string{"PATH=/"},
		Tmpfs:  []forkd.Tmpfs{{Path: "/tmp", SizeBytes: 512 << 20}},
		Cgroup: seedLimits,
	})
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	return info
}

func waitFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if b, _ := os.ReadFile(path); strings.Contains(string(b), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	b, _ := os.ReadFile(path)
	t.Fatalf("%s lacks %q: %q", path, want, b)
}

func TestForkdStartupRefusals(t *testing.T) {
	needsHost(t)
	bin := forkdBinary(t)
	for _, tc := range []struct{ flag, assertion string }{
		{"--TESTONLY-unsafe-nonroot", "production_mode"},
		{"--platform=systrap", "platform_kvm"},
		{"--debug-log=/tmp/forkd-test.log", "no_shared_log_files"},
		{"--debug", "no_shared_log_files"},
		{"--fork-namespaces=none", "fork_namespaces"},
		{"--fork-namespaces=ipc", "fork_namespaces"},
		{"--rootless", "not_rootless"},
		{"--directfs=true", "no_directfs"},
		{"--network=host", "network_mode"},
	} {
		t.Run(tc.assertion+tc.flag, func(t *testing.T) {
			state := t.TempDir()
			var stderr bytes.Buffer
			cmd := exec.Command(bin, "--forkd-state-dir="+state, "--forkd-allow-unlimited-children", tc.flag)
			cmd.Stderr = &stderr
			done := make(chan error, 1)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("forkd started with %s", tc.flag)
				}
			case <-time.After(20 * time.Second):
				cmd.Process.Kill()
				t.Fatalf("forkd did not refuse %s", tc.flag)
			}
			if !strings.Contains(stderr.String(), tc.assertion) {
				t.Errorf("forkd refused %s without naming %s:\n%s", tc.flag, tc.assertion, stderr.String())
			}
			if _, err := os.Stat(filepath.Join(state, "forkd.sock")); err == nil {
				t.Error("forkd created its socket before it refused")
			}
		})
	}
	t.Run("missing cgroup parent", func(t *testing.T) {
		out, err := exec.Command(bin, "--forkd-state-dir="+t.TempDir()).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "cgroup_parent") {
			t.Errorf("forkd without a cgroup parent = %v\n%s", err, out)
		}
	})
	t.Run("wrong runsc digest", func(t *testing.T) {
		out, err := exec.Command(bin, "--forkd-state-dir="+t.TempDir(), "--forkd-allow-unlimited-children", "--forkd-expect-runsc-sha256="+strings.Repeat("0", 64)).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "SHA-256") {
			t.Errorf("forkd with a wrong runsc digest = %v\n%s", err, out)
		}
	})
}

func TestForkdLifecycle(t *testing.T) {
	needsHost(t)
	d := startForkd(t)
	c := d.dial()
	hello, err := c.Hello()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range hello.Assertions {
		if !a.OK {
			t.Errorf("assertion %s failed: %s", a.Name, a.Detail)
		}
		t.Logf("assertion %-22s ok=%v %s", a.Name, a.OK, a.Detail)
	}
	if hello.RunscSHA256 == "" || hello.SentrySHA256 == "" {
		t.Errorf("hello lacks binary digests: %+v", hello)
	}

	// A seed with the wrong digest does not boot.
	image, digest := buildBusyboxImage(t, t.TempDir())
	if _, err := c.Seed(&forkd.SeedRequest{SeedID: "bad", Image: image, ImageSHA256: strings.Repeat("a", 64), Args: []string{"/busybox", "true"}, Cgroup: seedLimits}); err == nil || !strings.Contains(err.Error(), forkd.CodePermissionDenied) {
		t.Errorf("Seed with a wrong digest = %v, want permission_denied", err)
	}
	_ = digest

	seed := seedBusybox(t, c, "bb")
	t.Logf("seed ready in %d ms, attestation: %v", seed.ReadyMS, seed.Attestation)
	if len(seed.Attestation) == 0 {
		t.Error("the seed has no attestation")
	}

	// Exit code and output.
	child, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: "exit5", Env: []string{"CHILD_EXIT=5"}, Cgroup: limits})
	if err != nil {
		t.Fatalf("Fork: %v", err)
	}
	t.Logf("fork took %.1f ms, attestation: %v", child.ForkMS, child.Attestation)
	got, err := c.Wait("exit5", 30_000)
	if err != nil || got.State != forkd.StateExited || got.Exit.Reason != forkd.ReasonExited || got.Exit.ExitCode == nil || *got.Exit.ExitCode != 5 {
		t.Fatalf("Wait = %+v, %v, want exit code 5", got, err)
	}
	waitFile(t, got.StdoutPath, "CHILD_EXIT=5")
	if _, err := os.Stat(child.CgroupPath); !os.IsNotExist(err) {
		t.Errorf("cgroup %s remains after the child exited: %v", child.CgroupPath, err)
	}
	if err := c.DeleteChild("exit5"); err != nil {
		t.Fatal(err)
	}

	// N children held alive, each in its own cgroup with its limits.
	for _, n := range []int{1, 4, 16} {
		var kids []*forkd.ChildInfo
		for i := 0; i < n; i++ {
			k, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: fmt.Sprintf("held-%d-%d", n, i), Env: []string{"CHILD_HOLD=1"}, Cgroup: limits})
			if err != nil {
				t.Fatalf("Fork %d/%d: %v", i, n, err)
			}
			kids = append(kids, k)
		}
		pids := map[int]bool{}
		netns := map[string]bool{}
		for _, k := range kids {
			waitFile(t, k.StdoutPath, "READY")
			pids[k.PID] = true
			netns[readlink(t, fmt.Sprintf("/proc/%d/ns/net", k.PID))] = true
			if procs, _ := os.ReadFile(filepath.Join(k.CgroupPath, "cgroup.procs")); !strings.Contains(string(procs), fmt.Sprint(k.PID)) {
				t.Errorf("child %s is not in its cgroup %s: %q", k.ChildID, k.CgroupPath, procs)
			}
			for file, want := range map[string]string{"pids.max": "64", "memory.max": fmt.Sprint(256 << 20), "memory.swap.max": "0"} {
				if b, _ := os.ReadFile(filepath.Join(k.CgroupPath, file)); strings.TrimSpace(string(b)) != want {
					t.Errorf("%s of %s = %q, want %s", file, k.ChildID, b, want)
				}
			}
		}
		if len(pids) != n || len(netns) != n {
			t.Errorf("N=%d: %d distinct sandbox pids and %d distinct network namespaces", n, len(pids), len(netns))
		}
		_, listed, err := c.List()
		if err != nil || len(listed) != n {
			t.Errorf("N=%d: List returned %d children, %v", n, len(listed), err)
		}
		if n == 4 {
			// An exit that nobody asked for is seen, and does not touch the others.
			if err := unix.Kill(kids[0].PID, unix.SIGKILL); err != nil {
				t.Fatal(err)
			}
			w, err := c.Wait(kids[0].ChildID, 15_000)
			if err != nil || w.State != forkd.StateExited || w.Exit.Reason != forkd.ReasonKilled {
				t.Errorf("Wait for a killed child = %+v, %v, want reason killed", w, err)
			}
			for _, k := range kids[1:] {
				if w, _ := c.Wait(k.ChildID, 0); w == nil || w.State != forkd.StateRunning {
					t.Errorf("a sibling of the killed child stopped: %+v", w)
				}
			}
		}
		for _, k := range kids {
			if err := c.DeleteChild(k.ChildID); err != nil {
				t.Errorf("DeleteChild %s: %v", k.ChildID, err)
			}
			if _, err := os.Stat(k.CgroupPath); !os.IsNotExist(err) {
				t.Errorf("cgroup %s remains after delete: %v", k.CgroupPath, err)
			}
		}
		if _, listed, _ := c.List(); len(listed) != 0 {
			t.Errorf("N=%d: children remain after delete: %d", n, len(listed))
		}
	}

	// Deleting the seed removes the template.
	if err := c.DeleteSeed("bb"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(seed.PID, 0); err == nil {
		time.Sleep(500 * time.Millisecond)
		if err := unix.Kill(seed.PID, 0); err == nil {
			t.Errorf("the template process %d still runs after DeleteSeed", seed.PID)
		}
	}
}

func readlink(t *testing.T, p string) string {
	t.Helper()
	l, err := os.Readlink(p)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestForkdNetworkPerChild(t *testing.T) {
	needsHost(t)
	d := startForkd(t)
	c := d.dial()
	seedBusybox(t, c, "bb")
	var guestIPs []string
	for i := 0; i < 2; i++ {
		host, guest := fmt.Sprintf("198.18.%d.1/30", 80+i), fmt.Sprintf("198.18.%d.2/30", 80+i)
		k, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: fmt.Sprintf("net%d", i), Env: []string{"CHILD_LISTEN=1"}, Cgroup: limits,
			Net: &forkd.Net{Veth: &forkd.Veth{HostCIDR: host, GuestCIDR: guest}}})
		if err != nil {
			t.Fatalf("Fork %d: %v", i, err)
		}
		waitFile(t, k.StdoutPath, "READY")
		guestIPs = append(guestIPs, strings.TrimSuffix(guest, "/30"))
	}
	for i, ip := range guestIPs {
		var conn net.Conn
		var err error
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if conn, err = net.DialTimeout("tcp", ip+":8080", time.Second); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("child %d does not serve %s:8080 on its own veth: %v", i, ip, err)
		}
		conn.Close()
		w, err := c.Wait(fmt.Sprintf("net%d", i), 15_000)
		if err != nil || w.State != forkd.StateExited || w.Exit.Reason != forkd.ReasonExited {
			t.Errorf("child %d after the connection: %+v, %v", i, w, err)
		}
		if err := c.DeleteChild(fmt.Sprintf("net%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	links, _ := os.ReadDir("/sys/class/net")
	for _, l := range links {
		if strings.HasPrefix(l.Name(), "fdh") {
			t.Errorf("host veth %s remains after the children were deleted", l.Name())
		}
	}
}

// TestForkdSeedCgroup checks that the seed's processes run in the capped cgroup
// from the start, that the cap is a real limit, and that children do not run
// in the seed's cgroup.
func TestForkdSeedCgroup(t *testing.T) {
	needsHost(t)
	d := startForkd(t)
	c := d.dial()
	image, digest := buildBusyboxImage(t, t.TempDir())
	req := func(id string, cg *forkd.Cgroup) *forkd.SeedRequest {
		return &forkd.SeedRequest{SeedID: id, Image: image, ImageSHA256: digest,
			Args: []string{"/busybox", "sh", "-c", guest}, Env: []string{"PATH=/"},
			Tmpfs: []forkd.Tmpfs{{Path: "/tmp", SizeBytes: 64 << 20}}, Cgroup: cg}
	}

	// A seed without a limit is refused: forkd runs with a cgroup parent.
	if _, err := c.Seed(req("nolimit", nil)); err == nil || !strings.Contains(err.Error(), forkd.CodeInvalidArgument) {
		t.Errorf("Seed with no cgroup = %v, want invalid_argument", err)
	}

	read := func(dir, name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	seed, err := c.Seed(req("capped", &forkd.Cgroup{MemoryMax: 512 << 20, PidsMax: 512}))
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if want := filepath.Join(d.parent, "_seed.capped"); seed.CgroupPath != want {
		t.Fatalf("seed cgroup = %q, want %q", seed.CgroupPath, want)
	}
	for name, want := range map[string]string{"memory.max": fmt.Sprint(512 << 20), "pids.max": "512", "memory.swap.max": "0"} {
		if got := read(seed.CgroupPath, name); got != want {
			t.Errorf("seed %s = %q, want %q", name, got, want)
		}
	}
	// Every process of the template tree is in the leaf, and charged to it.
	procs := strings.Fields(read(seed.CgroupPath, "cgroup.procs"))
	if len(procs) < 2 {
		t.Errorf("the seed cgroup holds %d processes %v, want the template tree", len(procs), procs)
	}
	if cur := read(seed.CgroupPath, "memory.current"); cur == "0" {
		t.Errorf("the seed cgroup is charged no memory: the template did not boot inside it")
	}
	t.Logf("seed cgroup: procs=%v memory.current=%s memory.peak=%s", procs, read(seed.CgroupPath, "memory.current"), read(seed.CgroupPath, "memory.peak"))

	// A child lives in its own leaf and the seed's charge does not grow with it.
	child, err := c.Fork(&forkd.ForkRequest{SeedID: "capped", ChildID: "k1", Env: []string{"CHILD_HOLD=1"}, Cgroup: limits})
	if err != nil {
		t.Fatal(err)
	}
	if child.CgroupPath == seed.CgroupPath || filepath.Dir(child.CgroupPath) != d.parent {
		t.Errorf("child cgroup %q should be a sibling of the seed's %q", child.CgroupPath, seed.CgroupPath)
	}
	if cp := read(child.CgroupPath, "cgroup.procs"); strings.Contains(read(seed.CgroupPath, "cgroup.procs"), cp) {
		t.Errorf("child process %s is also in the seed cgroup", cp)
	}
	// What the guest sees as memory is the seed's memory.max.
	waitFile(t, child.StdoutPath, "READY")
	if err := c.DeleteSeed("capped"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(seed.CgroupPath); !os.IsNotExist(err) {
		t.Errorf("the seed's cgroup remains after the seed is deleted: %v", err)
	}
	if _, err := os.Stat(child.CgroupPath); !os.IsNotExist(err) {
		t.Errorf("the child's cgroup remains after the seed is deleted: %v", err)
	}

	// A cap below what the template needs to boot kills it: the limit is real.
	if _, err := c.Seed(req("tiny", &forkd.Cgroup{MemoryMax: 6 << 20})); err == nil {
		t.Errorf("a seed with memory.max=6M booted")
	} else {
		t.Logf("seed with memory.max=6M: %v", err)
	}
	if _, err := os.Stat(filepath.Join(d.parent, "_seed.tiny")); !os.IsNotExist(err) {
		t.Errorf("the failed seed's cgroup remains: %v", err)
	}
	if seeds, _, _ := c.List(); len(seeds) != 0 {
		t.Errorf("forkd still lists seeds after both are gone: %+v", seeds)
	}
}

func TestForkdLimitsAreEnforced(t *testing.T) {
	needsHost(t)
	d := startForkd(t)
	c := d.dial()
	seedBusybox(t, c, "bb")

	// Memory: 200 MB of tmpfs pages under a 96 MB memory.max kill the child; with
	// a 512 MB limit the same child finishes. A child above memory.high is only
	// throttled and stays alive for ages, so forkd refuses a limit with no
	// memory_max (protocol 2) and the kernel's OOM kill is the only memory limit.
	if _, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: "throttle", Cgroup: &forkd.Cgroup{PidsMax: 64, MemoryHigh: 96 << 20}}); err == nil || !strings.Contains(err.Error(), forkd.CodeInvalidArgument) {
		t.Errorf("Fork with memory_high and no memory_max = %v, want invalid_argument", err)
	}
	small := &forkd.Cgroup{PidsMax: 64, MemoryMax: 96 << 20}
	if _, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: "oom", Env: []string{"CHILD_ALLOC_MB=200"}, Cgroup: small}); err != nil {
		t.Fatal(err)
	}
	w, err := c.Wait("oom", 60_000)
	if err != nil || w.State != forkd.StateExited {
		t.Fatalf("Wait = %+v, %v", w, err)
	}
	t.Logf("memory-limited child ended: %+v", w.Exit)
	if w.Exit.Reason == forkd.ReasonExited && w.Exit.ExitCode != nil && *w.Exit.ExitCode == 0 {
		t.Errorf("a child that writes 200 MB survived memory.max=96M: %+v", w.Exit)
	}
	big := &forkd.Cgroup{PidsMax: 64, MemoryHigh: 480 << 20, MemoryMax: 512 << 20}
	if _, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: "fits", Env: []string{"CHILD_ALLOC_MB=100"}, Cgroup: big}); err != nil {
		t.Fatal(err)
	}
	w, err = c.Wait("fits", 60_000)
	if err != nil || w.Exit == nil || w.Exit.Reason != forkd.ReasonExited || *w.Exit.ExitCode != 0 {
		t.Errorf("the child with room to write 100 MB = %+v, %v, want a clean exit", w, err)
	}

	// pids.max below what the sentry needs: the child cannot run.
	tiny := &forkd.Cgroup{PidsMax: 6, MemoryHigh: 192 << 20, MemoryMax: 256 << 20}
	k, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: "pids", Env: []string{"CHILD_HOLD=1"}, Cgroup: tiny})
	if err != nil {
		t.Logf("pids.max=6: Fork failed as expected: %v", err)
	} else {
		w, err := c.Wait(k.ChildID, 20_000)
		if err != nil || w.State != forkd.StateExited {
			t.Errorf("pids.max=6: the child still runs: %+v, %v", w, err)
		} else {
			t.Logf("pids.max=6: child ended: %+v", w.Exit)
		}
	}

	// Deadline and output cap.
	if _, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: "life", Env: []string{"CHILD_HOLD=1"}, Cgroup: limits, MaxLifetimeMS: 1500}); err != nil {
		t.Fatal(err)
	}
	if w, err := c.Wait("life", 20_000); err != nil || w.Exit == nil || w.Exit.Reason != forkd.ReasonMaxLifetime {
		t.Errorf("max lifetime: %+v, %v", w, err)
	}
	if _, err := c.Fork(&forkd.ForkRequest{SeedID: "bb", ChildID: "logs", Env: []string{"CHILD_HOLD=1"}, Cgroup: limits, LogBytesLimit: 10}); err != nil {
		t.Fatal(err)
	}
	if w, err := c.Wait("logs", 20_000); err != nil || w.Exit == nil || w.Exit.Reason != forkd.ReasonLogLimit {
		t.Errorf("log limit: %+v, %v", w, err)
	}
}

// waitOutput polls a file until it holds a complete JSON object that contains
// want.
func waitOutput(path, want string, timeout time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(path)
		if t := bytes.TrimSpace(b); bytes.Contains(b, []byte(want)) && len(t) > 0 && t[len(t)-1] == '}' {
			return b, true
		}
		time.Sleep(200 * time.Microsecond)
	}
	b, _ := os.ReadFile(path)
	return b, false
}

// TestForkdEngine forks children that run a scan engine from a digest-pinned
// image, N at a time, and reports the latency through forkd.
func TestForkdEngine(t *testing.T) {
	needsHost(t)
	image := os.Getenv("FORKD_ENGINE_IMAGE")
	if image == "" {
		t.Skip("set FORKD_ENGINE_IMAGE to run the engine test")
	}
	sum, err := exec.Command("sha256sum", image).Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Fields(string(sum))[0]
	d := startForkd(t)
	c := d.dial()
	var env []string
	if v := os.Getenv("FORKD_ENGINE_ENV"); v != "" {
		env = strings.Split(v, ",")
	}
	seed, err := c.Seed(&forkd.SeedRequest{SeedID: "eng", Image: image, ImageSHA256: digest, Args: strings.Fields(os.Getenv("FORKD_ENGINE_ARGS")), Env: env, Cwd: "/", Cgroup: &forkd.Cgroup{MemoryMax: 2 << 30}})
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	t.Logf("FORKD_ENGINE seed ready_ms=%d", seed.ReadyMS)
	target := os.Getenv("FORKD_ENGINE_TARGET")
	engineLimits := &forkd.Cgroup{PidsMax: 64, MemoryHigh: 192 << 20, MemoryMax: 256 << 20}
	reps := 3
	for _, n := range []int{1, 4, 16} {
		var forkMS, resultMS []float64
		for rep := 0; rep < reps; rep++ {
			var wg sync.WaitGroup
			var mu sync.Mutex
			start := time.Now()
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					cc := d.dial()
					id := fmt.Sprintf("e-%d-%d-%d", n, rep, i)
					k, err := cc.Fork(&forkd.ForkRequest{SeedID: "eng", ChildID: id, Env: []string{"SCAN_TARGET=" + target}, Cgroup: engineLimits})
					if err != nil {
						t.Errorf("Fork %s: %v", id, err)
						return
					}
					// The engine holds after it printed its result, like the forkbench
					// harness expects: wait for the output, then delete the child.
					out, ok := waitOutput(k.StdoutPath, `"results"`, 120*time.Second)
					if !ok {
						w, _ := cc.Wait(id, 0)
						t.Errorf("%s printed no result: %.200q state %+v", id, out, w)
						return
					}
					mu.Lock()
					forkMS = append(forkMS, k.ForkMS)
					resultMS = append(resultMS, float64(time.Since(start).Microseconds())/1000)
					mu.Unlock()
					_ = cc.DeleteChild(id)
				}(i)
			}
			wg.Wait()
		}
		sort.Float64s(forkMS)
		sort.Float64s(resultMS)
		if len(forkMS) > 0 {
			t.Logf("FORKD_ENGINE n=%d children=%d fork_ms_med=%.1f fork_ms_p95=%.1f result_ms_med=%.1f result_ms_p95=%.1f",
				n, len(forkMS), forkMS[len(forkMS)/2], forkMS[len(forkMS)*95/100], resultMS[len(resultMS)/2], resultMS[len(resultMS)*95/100])
		}
	}
}
