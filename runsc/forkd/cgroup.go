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
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// cgroup2Magic is the f_type of a cgroup v2 file system.
const cgroup2Magic = 0x63677270

// cgroupMount is where the unified hierarchy is mounted. The cgroup path of a
// fork is relative to it.
const cgroupMount = "/sys/fs/cgroup"

// cgroupParent is the directory under which forkd creates one leaf per child.
type cgroupParent struct {
	// dir is the absolute path.
	dir string
}

// checkCgroupParent verifies that dir is a cgroup v2 directory below the
// mount, with the controllers that the children's limits need delegated.
func checkCgroupParent(dir string) (*cgroupParent, error) {
	dir = filepath.Clean(dir)
	if !strings.HasPrefix(dir, cgroupMount+"/") {
		return nil, fmt.Errorf("cgroup parent %q is not below %s", dir, cgroupMount)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return nil, fmt.Errorf("cgroup parent: %w", err)
	}
	if st.Type != cgroup2Magic {
		return nil, fmt.Errorf("cgroup parent %q is not on a cgroup v2 file system", dir)
	}
	data, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return nil, fmt.Errorf("cgroup parent: %w", err)
	}
	have := map[string]bool{}
	for _, c := range strings.Fields(string(data)) {
		have[c] = true
	}
	for _, need := range []string{"memory", "pids"} {
		if !have[need] {
			return nil, fmt.Errorf("cgroup parent %q does not delegate the %s controller to its children (cgroup.subtree_control = %q)", dir, need, strings.TrimSpace(string(data)))
		}
	}
	return &cgroupParent{dir: dir}, nil
}

// validCPUMax reports whether s is a cpu.max value: "max", "<quota>" or
// "<quota> <period>" with positive decimals, or "max <period>".
func validCPUMax(s string) bool {
	f := strings.Fields(s)
	if len(f) == 0 || len(f) > 2 {
		return false
	}
	if f[0] != "max" {
		if v, err := strconv.ParseUint(f[0], 10, 64); err != nil || v == 0 {
			return false
		}
	}
	if len(f) == 2 {
		if v, err := strconv.ParseUint(f[1], 10, 64); err != nil || v == 0 {
			return false
		}
	}
	return true
}

// validate checks the limits without touching the host.
func (c *Cgroup) validate(requireLimits bool) error {
	if c == nil {
		if requireLimits {
			return fmt.Errorf("a cgroup with pids_max and a memory limit is required")
		}
		return nil
	}
	if c.MemoryHigh < 0 || c.MemoryMax < 0 || c.PidsMax < 0 {
		return fmt.Errorf("cgroup limits must not be negative")
	}
	if c.MemoryHigh > 0 && c.MemoryMax > 0 && c.MemoryHigh > c.MemoryMax {
		return fmt.Errorf("memory_high %d is above memory_max %d", c.MemoryHigh, c.MemoryMax)
	}
	if c.CPUMax != "" && !validCPUMax(c.CPUMax) {
		return fmt.Errorf("invalid cpu_max %q", c.CPUMax)
	}
	if requireLimits && (c.PidsMax == 0 || (c.MemoryHigh == 0 && c.MemoryMax == 0)) {
		return fmt.Errorf("a cgroup with pids_max and a memory limit is required")
	}
	return nil
}

// childCgroup is the leaf of one child.
type childCgroup struct {
	dir string
}

// create makes the leaf and writes the limits. It must run before the fork:
// the child moves into the leaf before its guest runs.
func (p *cgroupParent) create(id string, c *Cgroup) (*childCgroup, error) {
	if err := ValidID(id); err != nil {
		return nil, err
	}
	dir := filepath.Join(p.dir, id)
	if err := os.Mkdir(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating cgroup %q: %w", dir, err)
	}
	cg := &childCgroup{dir: dir}
	write := func(file, val string) error {
		// Open without O_CREATE: a missing file means that the controller is not
		// delegated, and creating files in cgroupfs fails with a confusing error.
		f, err := os.OpenFile(filepath.Join(dir, file), os.O_WRONLY, 0)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%s of %q does not exist: the controller is not delegated by %q", file, dir, p.dir)
			}
			return fmt.Errorf("opening %s of %q: %w", file, dir, err)
		}
		defer f.Close()
		if _, err := f.WriteString(val); err != nil {
			return fmt.Errorf("writing %s of %q: %w", file, dir, err)
		}
		return nil
	}
	limits := []struct{ file, val string }{
		{"memory.swap.max", "0"},
	}
	if c != nil {
		if c.CPUMax != "" {
			limits = append(limits, struct{ file, val string }{"cpu.max", c.CPUMax})
		}
		if c.MemoryHigh > 0 {
			limits = append(limits, struct{ file, val string }{"memory.high", strconv.FormatInt(c.MemoryHigh, 10)})
		}
		if c.MemoryMax > 0 {
			limits = append(limits, struct{ file, val string }{"memory.max", strconv.FormatInt(c.MemoryMax, 10)})
		}
		if c.PidsMax > 0 {
			limits = append(limits, struct{ file, val string }{"pids.max", strconv.FormatInt(c.PidsMax, 10)})
		}
	}
	for _, l := range limits {
		if err := write(l.file, l.val); err != nil {
			cg.remove()
			return nil, err
		}
	}
	return cg, nil
}

// relative is the path that the runtime takes: relative to the mount.
func (c *childCgroup) relative() string {
	return strings.TrimPrefix(c.dir, cgroupMount)
}

// oomKills reads the oom_kill counter of the leaf.
func (c *childCgroup) oomKills() int64 {
	data, err := os.ReadFile(filepath.Join(c.dir, "memory.events"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "oom_kill "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

// remove kills whatever is left in the leaf and deletes it. A leaf with
// processes cannot be removed, and a killed process leaves the leaf after a
// short delay, so it retries.
func (c *childCgroup) remove() {
	if c == nil || c.dir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(c.dir, "cgroup.kill"), []byte("1"), 0644)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := unix.Rmdir(c.dir)
		if err == nil || err == unix.ENOENT || time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
