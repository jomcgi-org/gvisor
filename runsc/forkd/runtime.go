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

import "os"

// Runtime is the part of gVisor that the server drives: it boots templates and
// forks children from them. gvisor.go implements it with runsc/container. The
// server only sees this interface, so its logic is tested without KVM.
type Runtime interface {
	// Platform is the platform that templates and children run on.
	Platform() string
	// CreateTemplate boots a template and returns once it can fork.
	CreateTemplate(TemplateSpec) (Template, error)
	// Reset removes every template and child that an earlier forkd left in the
	// runtime's state directory. forkd calls it once at startup.
	Reset() error
}

// TemplateSpec is what the runtime needs to boot a template.
type TemplateSpec struct {
	ID string
	// Dir is a private directory for the template's bundle and logs.
	Dir string
	// ImagePath is a path that opens the verified image, such as
	// /proc/self/fd/N.
	ImagePath string

	Args             []string
	Env              []string
	Cwd              string
	UID, GID         uint32
	DropCapabilities bool
	Tmpfs            []Tmpfs
	Workers          int
	CPUs             int

	// Stdout and Stderr are append-only files for the template's output.
	Stdout, Stderr *os.File
}

// Template is a booted template.
type Template interface {
	// PID is the host process ID of the template's outermost process. Its
	// descendants are the seed, its workers and the stub.
	PID() int
	// Fork starts a child. It returns once the child's guest runs.
	Fork(ForkSpec) (Child, error)
	// Destroy ends the template and every child still running.
	Destroy() error
}

// ForkSpec is what the runtime needs to fork one child.
type ForkSpec struct {
	ID string
	// Dir is a private directory for the child's bundle state.
	Dir string
	Env []string
	// CgroupPath is an existing cgroup v2 directory relative to the cgroup
	// mount, such as "/forkd/child-1". Empty means the template's cgroup.
	CgroupPath string
	// NetNSPath is a network namespace whose links become the child's. Empty
	// means a loopback interface only.
	NetNSPath   string
	DisableIPv6 bool

	// Stdout and Stderr are append-only files for the child's output.
	Stdout, Stderr *os.File
}

// Child is a forked sandbox.
type Child interface {
	// PID is the host process ID of the child's sandbox.
	PID() int
	// Wait blocks until the guest's root process exits and returns its wait
	// status. It returns an error if the sandbox dies without one.
	Wait() (WaitStatus, error)
	// Destroy kills the child if it runs and removes its state.
	Destroy() error
}

// WaitStatus is the exit status of the guest's root process.
type WaitStatus struct {
	// Exited is true if the process exited by itself; ExitCode is then valid.
	Exited   bool
	ExitCode int
	// Signal is the terminating signal if Exited is false.
	Signal int
}
