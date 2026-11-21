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

package tcp

import (
	"context"
	"fmt"

	cryptorand "gvisor.dev/gvisor/pkg/rand"
)

// afterLoad is invoked by stateify.
func (p *protocol) afterLoad(context.Context) {
	p.resetSecrets(p.stack.SecureRNG())
}

func (p *protocol) resetSecrets(rng cryptorand.RNG) {
	if n, err := rng.Reader.Read(p.seqnumSecret[:]); err != nil || n != len(p.seqnumSecret) {
		panic(fmt.Sprintf("rng.Reader.Read(seqnumSecret) failed: n=%d err=%v", n, err))
	}
	if n, err := rng.Reader.Read(p.tsOffsetSecret[:]); err != nil || n != len(p.tsOffsetSecret) {
		panic(fmt.Sprintf("rng.Reader.Read(tsOffsetSecret) failed: n=%d err=%v", n, err))
	}
}

// ResetRandomState replaces random state used for future TCP operations.
// Preconditions: p's stack must be externally quiesced.
func (p *protocol) ResetRandomState(rng cryptorand.RNG) {
	p.resetSecrets(rng)
	p.dispatcher.resetRandomState(p.stack.InsecureRNG())
}
