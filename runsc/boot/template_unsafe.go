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

package boot

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/moby/sys/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/runsc/config"
)

//go:nosplit
func _getpid() int {
	pid, _, _ := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	return int(pid)
}

//go:nosplit
func _close(fd int) {
	syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0)
}

//go:nosplit
func _accept(fd int) (int, syscall.Errno) {
	cfd, _, errno := syscall.RawSyscall(syscall.SYS_ACCEPT, uintptr(fd), 0, 0)
	return int(cfd), errno
}

//go:nosplit
func _execve(pathname, argv, envp uintptr) int {
	_, _, errno := syscall.RawSyscall(syscall.SYS_EXECVE, pathname, argv, envp)
	println("execve errno:", errno)
	panic("execve")
}

// cloneCtx carries state across the three nosplit callbacks of
// runtime.Clone. Pinned to a package var so the callbacks can reach it
// without escaping to the heap.
var cloneCtx = &struct {
	argv0              *byte
	argv               []*byte
	cfd                int
	stubFD             int
	loader             *Loader
	finishProcessSetup bool
	lastCap            int
	readyFD            int
}{}

// preclone runs once on both sides of runtime.Clone() before the runtime
// resumes. In the parent branch (pid != 0), execve into the templatestub
// reaper stub so the parent process becomes a minimal init. In the
// child branch (pid == 0), close the memfd used by the parent's execve; the
// child then continues into waiting() to accept the next Fork RPC.
//
//go:nosplit
func preclone(pid int) {
	if pid := _getpid(); pid != 1 {
		println("unexpected PID:", pid, "expected: 1")
		panic(pid)
	}
	if pid != 0 {
		if cloneCtx.finishProcessSetup {
			// The reaper stub needs no capability and no descriptor.
			if errno := dropStubPrivileges(); errno != 0 {
				println("stub privilege drop errno:", errno)
				syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 1, 0, 0)
				panic("exit_group failed")
			}
		}
		_execve(uintptr(unsafe.Pointer(cloneCtx.argv0)),
			uintptr(unsafe.Pointer(&cloneCtx.argv[0])), 0)
	}
	_close(cloneCtx.stubFD)
	cloneCtx.stubFD = -1
	if cloneCtx.finishProcessSetup {
		if errno := dropTemplateExecCaps(); errno != 0 {
			println("template capability setup errno:", errno)
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 1, 0, 0)
			panic("exit_group failed")
		}
		if errno := reduceTemplateCaps(); errno != 0 {
			println("template capability reduction errno:", errno)
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 1, 0, 0)
			panic("exit_group failed")
		}
	}
}

// templateReady runs in the seed after all workers have been created.
//
//go:nosplit
func templateReady() {
	var ready byte = 1
	for {
		n, _, errno := syscall.RawSyscall(syscall.SYS_WRITE, uintptr(cloneCtx.readyFD), uintptr(unsafe.Pointer(&ready)), 1)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 || n != 1 {
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 1, 0, 0)
			panic("template readiness failed")
		}
		break
	}
	_close(cloneCtx.readyFD)
	cloneCtx.readyFD = -1
	_close(cloneCtx.loader.templateServerFD)
	if cloneCtx.finishProcessSetup {
		// The seed only waits for its workers from here on. The workers
		// were cloned already and keep the capability they need to fork.
		if errno := dropAllCaps(); errno != 0 {
			println("seed capability drop errno:", errno)
			syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 1, 0, 0)
			panic("exit_group failed")
		}
	}
}

// waiting runs in each worker with the runtime still stopped. It blocks on
// accept() on the template socket until the next fork RPC arrives, then
// stashes the accepted socket fd on cloneCtx for postclone.
//
//go:nosplit
func waiting() bool {
	if cloneCtx.readyFD >= 0 {
		_close(cloneCtx.readyFD)
		cloneCtx.readyFD = -1
	}
	for {
		cfd, errno := _accept(cloneCtx.loader.templateServerFD)
		if errno == 0 {
			cloneCtx.cfd = cfd
			break
		}
		if errno != syscall.EINTR {
			println("failed to accept:", errno)
			panic("accept")
		}
	}
	return true
}

// postclone runs once on both sides of runtime.Clone() after the
// runtime is stopped. In the parent branch the accepted socket fd
// belongs to the child and we just close our duplicate; in the child
// branch we close the template listening fd (the child is now serving
// the one accepted connection and will not accept more).
//
//go:nosplit
func postclone(pid int) {
	if pid != 0 {
		_close(cloneCtx.cfd)
	} else {
		if pid := _getpid(); pid != 1 {
			println("unexpected PID:", pid, "expected: 1")
			panic(pid)
		}
		_close(cloneCtx.loader.templateServerFD)
		if cloneCtx.finishProcessSetup {
			if errno := finishForkProcessSetup(); errno != 0 {
				println("fork process setup errno:", errno)
				syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 1, 0, 0)
				panic("exit_group failed")
			}
		}
	}
}

// closeRangeCloexec is CLOSE_RANGE_CLOEXEC, which golang.org/x/sys/unix does
// not define.
const closeRangeCloexec = 1 << 2

var (
	forkProcPath  = [...]byte{'/', 'p', 'r', 'o', 'c', 0}
	forkCapHeader = linux.CapUserHeader{Version: linux.LINUX_CAPABILITY_VERSION_3}
	forkCapData   [2]linux.CapUserData

	// templateCapData is the capability set the seed workers keep: only
	// CAP_SYS_ADMIN, which each fork needs to create the child's namespaces and
	// to unmount /proc in the child.
	templateCapData = [2]linux.CapUserData{{
		Effective: 1 << unix.CAP_SYS_ADMIN,
		Permitted: 1 << unix.CAP_SYS_ADMIN,
	}}
)

// dropAllCaps clears the effective, permitted and inheritable capability sets.
//
//go:nosplit
func dropAllCaps() syscall.Errno {
	_, _, errno := syscall.RawSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&forkCapHeader)), uintptr(unsafe.Pointer(&forkCapData[0])), 0)
	return errno
}

// reduceTemplateCaps drops every capability except CAP_SYS_ADMIN. It runs once
// in the seed, after dropTemplateExecCaps used CAP_SETPCAP for the last time.
// CAP_SYS_CHROOT was only needed to set up the chroot before the template
// booted.
//
//go:nosplit
func reduceTemplateCaps() syscall.Errno {
	_, _, errno := syscall.RawSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&forkCapHeader)), uintptr(unsafe.Pointer(&templateCapData[0])), 0)
	return errno
}

// dropStubPrivileges runs in the template process just before it executes the
// reaper stub. The stub only calls wait4, so it gets no capability, not even
// the ambient ones that would survive the execve, and every descriptor except
// the standard three closes at the execve.
//
//go:nosplit
func dropStubPrivileges() syscall.Errno {
	if _, _, errno := syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	if errno := dropAllCaps(); errno != 0 {
		return errno
	}
	_, _, errno := syscall.RawSyscall(unix.SYS_CLOSE_RANGE, 3, ^uintptr(0), closeRangeCloexec)
	return errno
}

// forkNamespaceFlags returns the clone flags for the namespaces named by the
// fork-namespaces setting.
func forkNamespaceFlags(setting string) (int, error) {
	list, err := config.ParseForkNamespaces(setting)
	if err != nil {
		return 0, err
	}
	var flags int
	for _, ns := range list {
		switch ns {
		case config.ForkNamespaceIPC:
			flags |= syscall.CLONE_NEWIPC
		case config.ForkNamespaceNet:
			flags |= syscall.CLONE_NEWNET
		case config.ForkNamespaceCgroup:
			flags |= unix.CLONE_NEWCGROUP
		}
	}
	return flags, nil
}

// dropTemplateExecCaps clears capability sets used by exec once, so children
// inherit them empty. The template keeps its effective capabilities to create
// child namespaces and remove procfs.
//
//go:nosplit
func dropTemplateExecCaps() syscall.Errno {
	for c := 0; c <= cloneCtx.lastCap; c++ {
		if _, _, errno := syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0, 0); errno != 0 {
			return errno
		}
	}
	if _, _, errno := syscall.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	return 0
}

// finishForkProcessSetup runs in the single-threaded child, before the runtime
// creates threads that must inherit the reduced capability sets.
//
//go:nosplit
func finishForkProcessSetup() syscall.Errno {
	if _, _, errno := syscall.RawSyscall(unix.SYS_UMOUNT2, uintptr(unsafe.Pointer(&forkProcPath[0])), unix.MNT_DETACH, 0); errno != 0 {
		return errno
	}
	_, _, errno := syscall.RawSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&forkCapHeader)), uintptr(unsafe.Pointer(&forkCapData[0])), 0)
	return errno
}

// clone fires runtime.Clone with the template's CLONE_NEW{NS,UTS,PID} flags
// and returns the accepted client socket fd in the child.
func (l *Loader) clone(stubPath string, stubFD int) int {
	var err error

	if cloneCtx.argv0, err = syscall.BytePtrFromString(stubPath); err != nil {
		panic(fmt.Errorf("failed to prepare argv0: %w", err))
	}
	if cloneCtx.argv, err = syscall.SlicePtrFromStrings([]string{
		"templatestub",
	}); err != nil {
		panic(fmt.Errorf("failed to prepare argv: %w", err))
	}
	cloneCtx.stubFD = stubFD
	cloneCtx.loader = l
	cloneCtx.readyFD = l.templateReadyFD
	cloneCtx.finishProcessSetup = !l.root.conf.TestOnlyAllowRunAsCurrentUserWithoutChroot
	if cloneCtx.finishProcessSetup {
		lastCap, err := capability.LastCap()
		if err != nil {
			panic(fmt.Errorf("reading last capability: %w", err))
		}
		cloneCtx.lastCap = int(lastCap)
	}

	defer func() { cloneCtx = nil }()

	// The mount, UTS and PID namespaces are always new. The IPC, network and
	// cgroup namespaces are new when the fork-namespaces setting names them.
	// CLONE_NEWIPC creates an mqueue superblock, and high sandbox churn can
	// make sget_fc() a latency bottleneck; see the fork-namespaces flag for the
	// measured cost. A user namespace is not created: with CLONE_NEWUSER
	// together with CLONE_NEWNS the inherited /proc mount is locked and the
	// child's umount2 fails with EINVAL, and the children have no capability and
	// the same kernel UID either way, so a user namespace would add no
	// credential separation.
	flags := int(syscall.SIGCHLD | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID)
	nsFlags, err := forkNamespaceFlags(l.root.conf.ForkNamespaces)
	if err != nil {
		// Config.Validate rejects this value before the sandbox starts.
		panic(fmt.Errorf("invalid fork-namespaces setting: %w", err))
	}
	flags |= nsFlags

	runtimeClone(preclone, waiting, postclone, flags, l.templateWorkers, templateReady)

	return cloneCtx.cfd
}
