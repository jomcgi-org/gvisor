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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Linux capability numbers that the assertions name.
const (
	capChown       = 0
	capSetgid      = 6
	capSetuid      = 7
	capSetpcap     = 8
	capNetAdmin    = 12
	capNetRaw      = 13
	capSysModule   = 16
	capSysRawio    = 17
	capSysChroot   = 18
	capSysAdmin    = 21
	capSysBoot     = 22
	capSysTime     = 25
	capMacOverride = 32
	capMacAdmin    = 33
)

// Settings are the host and runsc settings that decide whether forkd may run.
// The gVisor adapter fills it from runsc's config; tests fill it by hand.
type Settings struct {
	// TestOnlyUnsafe is true if runsc runs sandboxes as the current user without
	// a chroot (--TESTONLY-unsafe-nonroot). The children are then not isolated.
	TestOnlyUnsafe  bool
	DisableSeccomp  bool
	Rootless        bool
	DirectFS        bool
	Platform        string
	Network         string // "sandbox" or "none"
	Debug           bool   // debug logging, strace or packet logging: shared log files
	DebugLog        string
	ForkNamespaces  []string // namespaces besides mnt, uts and pid that children get of their own
	KVMDevicePath   string   // defaults to /dev/kvm
	AllowNoCgroup   bool
	CgroupParentDir string
}

// procStatus holds the fields of /proc/<pid>/status that the assertions read.
type procStatus struct {
	PPid       int
	NoNewPrivs int
	Seccomp    int
	CapEff     uint64
	CapPrm     uint64
	CapBnd     uint64
	CapAmb     uint64
}

func parseProcStatus(data string) (procStatus, error) {
	var st procStatus
	seen := 0
	for _, line := range strings.Split(data, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		hexv := func() uint64 { v, _ := strconv.ParseUint(val, 16, 64); return v }
		dec := func() int { v, _ := strconv.Atoi(val); return v }
		switch key {
		case "PPid":
			st.PPid = dec()
		case "NoNewPrivs":
			st.NoNewPrivs = dec()
			seen++
		case "Seccomp":
			st.Seccomp = dec()
			seen++
		case "CapEff":
			st.CapEff = hexv()
			seen++
		case "CapPrm":
			st.CapPrm = hexv()
		case "CapBnd":
			st.CapBnd = hexv()
		case "CapAmb":
			st.CapAmb = hexv()
		}
	}
	if seen < 3 {
		return st, fmt.Errorf("status lacks NoNewPrivs, Seccomp or CapEff")
	}
	return st, nil
}

func readProcStatus(pid int) (procStatus, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return procStatus{}, err
	}
	return parseProcStatus(string(data))
}

func capBit(c int) uint64 { return 1 << uint(c) }

// checkStartup runs the startup assertions of invariant I1 and returns every
// result. forkd refuses to serve if one fails.
func checkStartup(s Settings) []Assertion {
	var out []Assertion
	add := func(name string, ok bool, format string, args ...any) {
		out = append(out, Assertion{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
	}

	add("production_mode", !s.TestOnlyUnsafe && os.Geteuid() == 0,
		"children run as an unprivileged user in a chroot: TESTONLY-unsafe-nonroot=%v euid=%d (forkd must run as root)", s.TestOnlyUnsafe, os.Geteuid())
	add("sentry_seccomp", !s.DisableSeccomp, "disable-seccomp=%v", s.DisableSeccomp)
	add("not_rootless", !s.Rootless, "rootless=%v", s.Rootless)
	add("no_directfs", !s.DirectFS, "directfs=%v", s.DirectFS)
	add("platform_kvm", s.Platform == "kvm", "platform=%q", s.Platform)
	add("network_mode", s.Network == "sandbox" || s.Network == "none", "network=%q, want sandbox or none", s.Network)
	// A debug log, strace or packet log is one append-only file that the sandbox
	// processes of a seed share. A child could write to what its siblings read.
	add("no_shared_log_files", !s.Debug && s.DebugLog == "", "debug=%v debug-log=%q", s.Debug, s.DebugLog)

	ns := map[string]bool{}
	for _, n := range s.ForkNamespaces {
		ns[n] = true
	}
	add("fork_namespaces", ns["ipc"] && ns["net"], "fork-namespaces=%v, children need their own ipc and net namespaces", s.ForkNamespaces)

	dev := s.KVMDevicePath
	if dev == "" {
		dev = "/dev/kvm"
	}
	ok, detail := checkKVM(dev)
	add("kvm_present", ok, "%s", detail)

	st, err := readProcStatus(os.Getpid())
	if err != nil {
		add("capabilities", false, "reading own status: %v", err)
	} else {
		need := capBit(capSysAdmin) | capBit(capSysChroot) | capBit(capSetpcap) | capBit(capSetuid) | capBit(capSetgid)
		if s.Network == "sandbox" {
			need |= capBit(capNetAdmin) | capBit(capNetRaw)
		}
		forbid := capBit(capSysModule) | capBit(capSysRawio) | capBit(capSysBoot) | capBit(capSysTime) | capBit(capMacAdmin) | capBit(capMacOverride)
		missing := need &^ st.CapEff
		extra := forbid & st.CapBnd
		add("capabilities", missing == 0 && extra == 0,
			"CapEff=%#x CapBnd=%#x missing=%#x forbidden-in-bounding-set=%#x", st.CapEff, st.CapBnd, missing, extra)
		add("forkd_seccomp_state", true, "Seccomp=%d NoNewPrivs=%d (forkd itself may be unfiltered; children are checked after every fork)", st.Seccomp, st.NoNewPrivs)
	}

	if s.CgroupParentDir == "" {
		add("cgroup_parent", s.AllowNoCgroup, "no --cgroup-parent: children would run without limits (allow-unlimited-children=%v)", s.AllowNoCgroup)
	} else if _, err := checkCgroupParent(s.CgroupParentDir); err != nil {
		add("cgroup_parent", false, "%v", err)
	} else {
		add("cgroup_parent", true, "%s", s.CgroupParentDir)
	}
	return out
}

func failedAssertions(list []Assertion) []string {
	var failed []string
	for _, a := range list {
		if !a.OK {
			failed = append(failed, a.Name+": "+a.Detail)
		}
	}
	return failed
}

// checkKVM opens the device and asks for the API version, which is 12 on every
// kernel that gVisor supports.
func checkKVM(dev string) (bool, string) {
	fd, err := unix.Open(dev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Sprintf("opening %s: %v", dev, err)
	}
	defer unix.Close(fd)
	const kvmGetAPIVersion = 0xAE00
	v, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), kvmGetAPIVersion, 0)
	if errno != 0 {
		return false, fmt.Sprintf("KVM_GET_API_VERSION on %s: %v", dev, errno)
	}
	return v == 12, fmt.Sprintf("%s API version %d", dev, v)
}

// openImage opens the image for reading and returns its SHA-256. It refuses
// anything but a regular file that no other user can write: the digest covers
// the content at the time of the hash, and a writable file could change under
// the sentry afterwards. The returned file stays open: the caller boots from
// /proc/self/fd/N, which is the inode that was hashed, not a path that can be
// swapped.
func openImage(path string) (*os.File, string, error) {
	if !filepath.IsAbs(path) {
		return nil, "", fmt.Errorf("image path %q must be absolute", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", fmt.Errorf("opening image: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return nil, "", fmt.Errorf("image %q is not a regular file", path)
	}
	if st.Mode&0022 != 0 {
		f.Close()
		return nil, "", fmt.Errorf("image %q is writable by group or others (mode %o)", path, st.Mode&0777)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("hashing image: %w", err)
	}
	return f, hex.EncodeToString(h.Sum(nil)), nil
}

// FileSHA256 returns the hex SHA-256 digest of a file, or "" if it cannot be
// read.
func FileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// descendants returns pid and every process below it, scanning /proc once.
func descendants(root int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []int{root}
	}
	parent := map[int]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st, err := readProcStatus(pid)
		if err != nil {
			continue
		}
		parent[pid] = st.PPid
	}
	set := map[int]bool{root: true}
	for changed := true; changed; {
		changed = false
		for pid, ppid := range parent {
			if !set[pid] && set[ppid] {
				set[pid] = true
				changed = true
			}
		}
	}
	var out []int
	for pid := range set {
		out = append(out, pid)
	}
	return out
}

// attestSeed checks the privileges of every process of a booted seed: the stub,
// the seed and its workers may hold at most CAP_SYS_ADMIN, which the workers
// need to clone children into new namespaces. It returns what it read.
func attestSeed(templatePID int) (lines []string, err error) {
	var bad []string
	for _, pid := range descendants(templatePID) {
		st, rerr := readProcStatus(pid)
		if rerr != nil {
			continue // exited meanwhile
		}
		lines = append(lines, fmt.Sprintf("pid=%d CapEff=%#x CapPrm=%#x CapAmb=%#x NoNewPrivs=%d Seccomp=%d", pid, st.CapEff, st.CapPrm, st.CapAmb, st.NoNewPrivs, st.Seccomp))
		if extra := (st.CapEff | st.CapPrm | st.CapAmb) &^ capBit(capSysAdmin); extra != 0 {
			bad = append(bad, fmt.Sprintf("pid %d holds capabilities %#x besides CAP_SYS_ADMIN", pid, extra))
		}
	}
	if len(bad) > 0 {
		return lines, fmt.Errorf("seed privileges: %s", strings.Join(bad, "; "))
	}
	return lines, nil
}

// namespaces are the links in /proc/<pid>/ns that a child must not share with
// its worker.
var namespaceNames = []string{"mnt", "uts", "pid", "ipc", "net"}

func nsLink(pid int, name string) string {
	l, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, name))
	return l
}

// attestChild checks the state that invariant I1 promises for a forked child:
// the sentry's seccomp filter is on, no capabilities, no new privileges, and
// its own mount, UTS, PID, IPC and network namespaces. The worker that cloned it
// is its parent. It returns what it read.
func attestChild(pid int) (lines []string, err error) {
	st, err := readProcStatus(pid)
	if err != nil {
		return nil, fmt.Errorf("reading child status: %w", err)
	}
	lines = append(lines, fmt.Sprintf("pid=%d ppid=%d Seccomp=%d NoNewPrivs=%d CapEff=%#x CapPrm=%#x CapBnd=%#x CapAmb=%#x",
		pid, st.PPid, st.Seccomp, st.NoNewPrivs, st.CapEff, st.CapPrm, st.CapBnd, st.CapAmb))
	var bad []string
	if st.Seccomp != 2 {
		bad = append(bad, fmt.Sprintf("Seccomp=%d, want 2 (filter)", st.Seccomp))
	}
	if st.NoNewPrivs != 1 {
		bad = append(bad, fmt.Sprintf("NoNewPrivs=%d, want 1", st.NoNewPrivs))
	}
	if st.CapEff|st.CapPrm|st.CapAmb != 0 {
		bad = append(bad, fmt.Sprintf("capabilities CapEff=%#x CapPrm=%#x CapAmb=%#x, want none", st.CapEff, st.CapPrm, st.CapAmb))
	}
	for _, name := range namespaceNames {
		child, worker := nsLink(pid, name), nsLink(st.PPid, name)
		if child == "" || worker == "" || child == worker {
			bad = append(bad, fmt.Sprintf("%s namespace %q is the worker's %q", name, child, worker))
		}
	}
	if len(bad) > 0 {
		return lines, fmt.Errorf("child conformance: %s", strings.Join(bad, "; "))
	}
	return lines, nil
}
