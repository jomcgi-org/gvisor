// Copyright 2018 The gVisor Authors.
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

package usage

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/memutil"
)

// RTMemoryStatsSize is the size of the RTMemoryStats struct.
var RTMemoryStatsSize = unsafe.Sizeof(RTMemoryStats{})

// RTMemoryStatsPointer casts addr to a RTMemoryStats pointer.
func RTMemoryStatsPointer(addr uintptr) *RTMemoryStats {
	return (*RTMemoryStats)(unsafe.Pointer(addr))
}

// RebindRTMemoryStats gives the calling process its own backing file for the
// real-time memory stats page. A process cloned from a template sandbox calls
// it: until then the clone holds the template's memfd, and so does every
// sibling.
//
// The new memfd starts with the current value of the stats page. It replaces
// the mapping at the same address and the old descriptor at the same
// descriptor number, so MemoryAccounting.File stays valid. Readers of the
// memory-usage file (runsc usage and events) then see this process's counters
// and no other process's.
//
// Precondition: no other thread may race with the replacement of the mapping.
func RebindRTMemoryStats() error {
	m := MemoryAccounting
	if m == nil || m.File == nil || m.RTMemoryStats == nil {
		return fmt.Errorf("memory accounting is not initialized")
	}
	fd, err := memutil.CreateMemFD("memory-usage", 0)
	if err != nil {
		return fmt.Errorf("creating private usage file: %w", err)
	}
	// The descriptor never becomes an os.File, so no finalizer can close a
	// recycled descriptor number.
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, int64(RTMemoryStatsSize)); err != nil {
		return fmt.Errorf("truncating private usage file: %w", err)
	}
	cur := m.RTMemoryStats.RTMapped.Load()
	if n, err := unix.Pwrite(fd, (*[8]byte)(unsafe.Pointer(&cur))[:], 0); err != nil || n != 8 {
		return fmt.Errorf("seeding private usage file: wrote %d bytes: %v", n, err)
	}
	addr := uintptr(unsafe.Pointer(m.RTMemoryStats))
	if _, _, errno := unix.Syscall6(unix.SYS_MMAP, addr, RTMemoryStatsSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_FIXED, uintptr(fd), 0); errno != 0 {
		return fmt.Errorf("mapping private usage file at %#x: %w", addr, errno)
	}
	if err := unix.Dup3(fd, int(m.File.Fd()), unix.O_CLOEXEC); err != nil {
		return fmt.Errorf("replacing usage file descriptor: %w", err)
	}
	return nil
}
