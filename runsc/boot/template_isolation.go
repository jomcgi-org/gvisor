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

	"gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// resetInheritedForkState gives a forked child its own copy of every writable
// host kernel object that the clone inherits from the template sandbox and
// that would otherwise be shared with the template and all sibling children:
//
//   - the scratch pipe of the gofer filesystem (both ends),
//   - the memfd behind the real-time memory stats page,
//   - the (empty) memfd of the main memory file, and
//   - the shared anonymous mapping that reserves the KVM ioeventfd addresses
//     (replaced by KVM.Reload).
//
// Without this, a compromised child holds a read-write channel to every
// sibling. It runs in the child before the guest resumes and before the
// seccomp filter is installed, because the filter forbids pipe2.
//
// Read-only descriptors that stay shared on purpose: the EROFS root image.
func resetInheritedForkState(l *Loader) error {
	if err := gofer.RebindTempPipe(); err != nil {
		return fmt.Errorf("fork isolation: %w", err)
	}
	if err := usage.RebindRTMemoryStats(); err != nil {
		return fmt.Errorf("fork isolation: %w", err)
	}
	if err := l.k.MemoryFile().RebindBackingFile(); err != nil {
		return fmt.Errorf("fork isolation: %w", err)
	}
	return nil
}
