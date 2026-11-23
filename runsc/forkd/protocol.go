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

// Package forkd implements forkd, a small local daemon that holds sandbox
// templates (seeds) and forks single-use child sandboxes from them for one
// caller, such as a worker process on the same host.
//
// The wire protocol is versioned JSON over a Unix stream socket. Every message
// is a 4 byte big-endian length followed by that many bytes of one JSON
// object. A connection serves one request at a time and answers each request
// with exactly one response, in order. A caller that needs a blocking call
// (seed, fork, wait) while it does other work opens another connection.
//
// JSON keeps the protocol debuggable with socat and jq, needs no code
// generation on the caller's side, and lets either side add optional fields
// without a version change. Both sides must ignore unknown fields. A change
// that removes or reinterprets a field, or adds a required one, bumps
// ProtocolVersion; forkd refuses requests of another version.
package forkd

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// ProtocolVersion is the version of the wire protocol that this package
// speaks.
const ProtocolVersion = 1

// MaxFrameBytes bounds one message. Requests carry identities, limits and
// environment entries, never request bodies.
const MaxFrameBytes = 1 << 20

// Operations.
const (
	// OpHello returns the version, the result of the startup assertions and the
	// digests of the binaries that forkd drives.
	OpHello = "hello"
	// OpSeed boots a template from a digest-pinned EROFS image and waits until
	// it can fork.
	OpSeed = "seed"
	// OpFork forks one single-use child from a seed.
	OpFork = "fork"
	// OpWait blocks until a child exits or a timeout expires.
	OpWait = "wait"
	// OpDelete kills and removes a child, or a seed with all its children.
	OpDelete = "delete"
	// OpList lists seeds and children.
	OpList = "list"
)

// Error codes.
const (
	CodeInvalidArgument    = "invalid_argument"
	CodeNotFound           = "not_found"
	CodeAlreadyExists      = "already_exists"
	CodeFailedPrecondition = "failed_precondition"
	CodePermissionDenied   = "permission_denied"
	CodeResourceExhausted  = "resource_exhausted"
	CodeUnavailable        = "unavailable"
	CodeInternal           = "internal"
)

// Child and seed states.
const (
	StateRunning = "running"
	StateExited  = "exited"
	StateReady   = "ready"
)

// Exit reasons.
const (
	// ReasonExited: the guest's root process exited; ExitCode is its status.
	ReasonExited = "exited"
	// ReasonKilled: the sandbox process died without reporting a status.
	ReasonKilled = "killed"
	// ReasonOOM: the sandbox process died and its cgroup recorded an OOM kill.
	ReasonOOM = "oom"
	// ReasonMaxLifetime: forkd killed the child at its deadline.
	ReasonMaxLifetime = "max_lifetime"
	// ReasonLogLimit: forkd killed the child because its output passed the cap.
	ReasonLogLimit = "log_limit"
	// ReasonDeleted: a delete request killed the child.
	ReasonDeleted = "deleted"
	// ReasonSeedGone: the seed was deleted, or its process died.
	ReasonSeedGone = "seed_gone"
)

// Request is one message from the caller to forkd.
type Request struct {
	Version int    `json:"version"`
	ID      string `json:"id,omitempty"`
	Op      string `json:"op"`

	Seed   *SeedRequest   `json:"seed,omitempty"`
	Fork   *ForkRequest   `json:"fork,omitempty"`
	Wait   *WaitRequest   `json:"wait,omitempty"`
	Delete *DeleteRequest `json:"delete,omitempty"`
}

// Response is forkd's answer to one Request. Exactly one of the result fields
// is set on success, depending on the operation.
type Response struct {
	Version int    `json:"version"`
	ID      string `json:"id,omitempty"`
	OK      bool   `json:"ok"`
	Error   *Error `json:"error,omitempty"`

	Hello    *HelloInfo  `json:"hello,omitempty"`
	Seed     *SeedInfo   `json:"seed,omitempty"`
	Child    *ChildInfo  `json:"child,omitempty"`
	Seeds    []SeedInfo  `json:"seeds,omitempty"`
	Children []ChildInfo `json:"children,omitempty"`
}

// Error is a failed operation.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// SeedRequest boots a template.
type SeedRequest struct {
	// SeedID names the seed. It becomes part of file names.
	SeedID string `json:"seed_id"`
	// Image is the absolute path of the read-only EROFS root image. The caller
	// builds it from digest-pinned layers.
	Image string `json:"image"`
	// ImageSHA256 is the hex SHA-256 digest that the image must have. forkd
	// hashes the file it will boot from and refuses to start on a mismatch.
	ImageSHA256 string `json:"image_sha256"`

	// Args, Env and Cwd are the guest's root process. Env is public: every child
	// inherits it. The seed must hold no secret.
	Args []string `json:"args"`
	Env  []string `json:"env,omitempty"`
	Cwd  string   `json:"cwd,omitempty"`
	// UID and GID are the guest user of the root process.
	UID uint32 `json:"uid,omitempty"`
	GID uint32 `json:"gid,omitempty"`
	// DropCapabilities starts the guest with an empty capability set.
	DropCapabilities bool `json:"drop_capabilities,omitempty"`
	// Tmpfs are in-memory file systems of the guest. Their pages are charged to
	// the child that writes them.
	Tmpfs []Tmpfs `json:"tmpfs,omitempty"`

	// Workers is the number of template worker processes that serve forks.
	// Zero means one. A worker that dies ends the seed and all its children.
	Workers int `json:"workers,omitempty"`
	// CPUs is the number of CPUs the guest sees. Zero means one.
	CPUs int `json:"cpus,omitempty"`
}

// Tmpfs is an in-memory mount of the guest.
type Tmpfs struct {
	Path      string `json:"path"`
	SizeBytes uint64 `json:"size_bytes,omitempty"`
}

// ForkRequest forks one child.
type ForkRequest struct {
	SeedID string `json:"seed_id"`
	// ChildID names the child. It becomes part of file and cgroup names.
	ChildID string `json:"child_id"`
	// Env is the child's spec environment. Only the control plane may fill it:
	// forkd parses it before the child's seccomp filter is on, so it must never
	// carry request content. forkd limits the number and size of the entries.
	Env []string `json:"env,omitempty"`

	// Cgroup limits the child. forkd creates the leaf and the child moves into
	// it before its guest runs. It is required unless forkd runs with
	// --allow-unlimited-children.
	Cgroup *Cgroup `json:"cgroup,omitempty"`
	// Net is the child's network. Without it the child has only a loopback
	// interface.
	Net *Net `json:"net,omitempty"`

	// MaxLifetimeMS kills the child after that many milliseconds. Zero means
	// forkd's default.
	MaxLifetimeMS int64 `json:"max_lifetime_ms,omitempty"`
	// LogBytesLimit kills the child when its stdout and stderr together pass
	// that many bytes. Zero means forkd's default.
	LogBytesLimit int64 `json:"log_bytes_limit,omitempty"`
}

// Cgroup are the limits of a child's cgroup.
type Cgroup struct {
	// CPUMax is the cpu.max value, "<quota> <period>" in microseconds, or "max".
	CPUMax string `json:"cpu_max,omitempty"`
	// MemoryHigh and MemoryMax are bytes. Swap is always disabled.
	MemoryHigh int64 `json:"memory_high,omitempty"`
	MemoryMax  int64 `json:"memory_max,omitempty"`
	// PidsMax bounds the processes and threads of the child's sandbox.
	PidsMax int64 `json:"pids_max,omitempty"`
}

// Net is the network of a child.
type Net struct {
	// NetNSPath is an existing network namespace, created by the caller. The
	// child's netstack takes over its links, addresses and routes. forkd does
	// not create or delete it.
	NetNSPath string `json:"netns_path,omitempty"`
	// Veth asks forkd to create a namespace with one veth pair: the guest end
	// inside it, the host end in forkd's namespace. forkd deletes both when the
	// child is gone. Exactly one of NetNSPath and Veth must be set.
	Veth *Veth `json:"veth,omitempty"`
	// DisableIPv6 drops IPv6 addresses and routes of the namespace.
	DisableIPv6 bool `json:"disable_ipv6,omitempty"`
}

// Veth is a veth pair that forkd creates for one child.
type Veth struct {
	// HostCIDR and GuestCIDR are the addresses of the two ends, for example
	// "198.18.7.1/30" and "198.18.7.2/30".
	HostCIDR  string `json:"host_cidr"`
	GuestCIDR string `json:"guest_cidr"`
}

// WaitRequest waits for a child to exit.
type WaitRequest struct {
	ChildID string `json:"child_id"`
	// TimeoutMS is how long to wait. Zero returns the current state at once.
	// A negative value waits until the child exits or the connection closes.
	TimeoutMS int64 `json:"timeout_ms,omitempty"`
}

// DeleteRequest deletes a child or a seed.
type DeleteRequest struct {
	// Kind is "child" or "seed".
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// HelloInfo describes forkd.
type HelloInfo struct {
	ForkdVersion    string      `json:"forkd_version"`
	ProtocolVersion int         `json:"protocol_version"`
	Platform        string      `json:"platform"`
	RunscSHA256     string      `json:"runsc_sha256,omitempty"`
	SentrySHA256    string      `json:"sentry_sha256,omitempty"`
	Assertions      []Assertion `json:"assertions"`
	MaxChildren     int         `json:"max_children"`
	Seeds           int         `json:"seeds"`
	Children        int         `json:"children"`
}

// Assertion is the result of one startup check.
type Assertion struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// SeedInfo describes a seed.
type SeedInfo struct {
	SeedID      string `json:"seed_id"`
	State       string `json:"state"`
	PID         int    `json:"pid"`
	ImageSHA256 string `json:"image_sha256"`
	Workers     int    `json:"workers"`
	CPUs        int    `json:"cpus"`
	Platform    string `json:"platform"`
	ReadyMS     int64  `json:"ready_ms"`
	CreatedUnix int64  `json:"created_unix_ms"`
	Children    int    `json:"children"`
	// Attestation is what forkd read from /proc about the seed's processes.
	Attestation []string `json:"attestation,omitempty"`
}

// ChildInfo describes a child.
type ChildInfo struct {
	ChildID    string `json:"child_id"`
	SeedID     string `json:"seed_id"`
	State      string `json:"state"`
	PID        int    `json:"pid"`
	StdoutPath string `json:"stdout_path"`
	StderrPath string `json:"stderr_path"`
	// CgroupPath is the absolute path of the child's cgroup, if it has one.
	CgroupPath string `json:"cgroup_path,omitempty"`
	NetNSPath  string `json:"netns_path,omitempty"`
	// ForkMS is how long the fork took inside forkd, from request to return.
	ForkMS      float64   `json:"fork_ms"`
	StartedUnix int64     `json:"started_unix_ms"`
	Exit        *ExitInfo `json:"exit,omitempty"`
	// Attestation is what forkd read from /proc about the child right after
	// the fork.
	Attestation []string `json:"attestation,omitempty"`
}

// ExitInfo is the end of a child.
type ExitInfo struct {
	Reason string `json:"reason"`
	// ExitCode is the guest's exit status when Reason is "exited".
	ExitCode *int `json:"exit_code,omitempty"`
	// Signal is the signal that ended the guest's root process, if any.
	Signal int `json:"signal,omitempty"`
	// OOMKills is the oom_kill counter of the child's cgroup.
	OOMKills int64  `json:"oom_kills,omitempty"`
	AtUnix   int64  `json:"at_unix_ms"`
	Detail   string `json:"detail,omitempty"`
}

var idRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// ValidID reports whether id is a safe name for a seed or child.
func ValidID(id string) error {
	if !idRegexp.MatchString(id) {
		return fmt.Errorf("invalid id %q: want 1-63 characters from [A-Za-z0-9_.-], starting with a letter or digit", id)
	}
	return nil
}

// WriteMessage writes v as one frame.
func WriteMessage(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > MaxFrameBytes {
		return fmt.Errorf("message of %d bytes exceeds the %d byte limit", len(data), MaxFrameBytes)
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

// ReadMessage reads one frame into v. It returns io.EOF only when the stream
// ends between frames.
func ReadMessage(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameBytes {
		return fmt.Errorf("frame of %d bytes exceeds the %d byte limit", n, MaxFrameBytes)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return json.Unmarshal(data, v)
}
