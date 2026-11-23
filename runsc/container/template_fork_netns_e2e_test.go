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

package container

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
)

// forkTestNetNS is a network namespace that exists as long as its holder
// thread does. Functions given to run execute on that thread, so they see the
// namespace.
type forkTestNetNS struct {
	fd   int
	jobs chan func()
	done chan struct{}
}

func newForkTestNetNS(t *testing.T) *forkTestNetNS {
	t.Helper()
	ns := &forkTestNetNS{jobs: make(chan func()), done: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		defer close(ns.done)
		// The thread stays locked, so it exits with this goroutine and the
		// namespace goes away with the last reference to it.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			started <- fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
			return
		}
		fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			started <- fmt.Errorf("opening the namespace: %w", err)
			return
		}
		ns.fd = fd
		started <- nil
		for job := range ns.jobs {
			job()
		}
	}()
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(ns.jobs)
		<-ns.done
		unix.Close(ns.fd)
	})
	return ns
}

// path names the namespace for as long as the test keeps the descriptor open.
func (n *forkTestNetNS) path() string { return fmt.Sprintf("/proc/self/fd/%d", n.fd) }

func (n *forkTestNetNS) id(t *testing.T) string {
	t.Helper()
	link, err := os.Readlink(n.path())
	if err != nil {
		t.Fatalf("Readlink(%s): %v", n.path(), err)
	}
	return link
}

func (n *forkTestNetNS) run(fn func()) {
	done := make(chan struct{})
	n.jobs <- func() { fn(); close(done) }
	<-done
}

// addPeer moves a veth end into the namespace and gives it an address.
func (n *forkTestNetNS) addPeer(t *testing.T, peer netlink.Link, addr *net.IPNet) {
	t.Helper()
	if err := netlink.LinkSetNsFd(peer, n.fd); err != nil {
		t.Fatalf("LinkSetNsFd(%s): %v", peer.Attrs().Name, err)
	}
	var err error
	n.run(func() {
		var link netlink.Link
		if link, err = netlink.LinkByName(peer.Attrs().Name); err != nil {
			return
		}
		if err = netlink.AddrAdd(link, &netlink.Addr{IPNet: addr}); err != nil {
			return
		}
		err = netlink.LinkSetUp(link)
	})
	if err != nil {
		t.Fatalf("configuring %s in the namespace: %v", peer.Attrs().Name, err)
	}
}

// addresses returns the IPv4 addresses of the interface that the host keeps in
// the namespace.
func (n *forkTestNetNS) addresses(t *testing.T, name string) []string {
	t.Helper()
	var (
		out []string
		err error
	)
	n.run(func() {
		var link netlink.Link
		if link, err = netlink.LinkByName(name); err != nil {
			return
		}
		var addrs []netlink.Addr
		if addrs, err = netlink.AddrList(link, netlink.FAMILY_V4); err != nil {
			return
		}
		for _, a := range addrs {
			out = append(out, a.IPNet.String())
		}
	})
	if err != nil {
		t.Fatalf("listing addresses of %s: %v", name, err)
	}
	return out
}

func socketFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if target, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.HasPrefix(target, "socket:") {
			count++
		}
	}
	return count
}

// TestTemplateForkNetNSPath forks children whose network comes from a network
// namespace that the host created for each of them: a veth end with an address,
// whose other end is on a bridge with a server that the guest connects to.
// The server only sees a connection from the right address if the child's
// netstack took over the links and addresses of its namespace.
func TestTemplateForkNetNSPath(t *testing.T) {
	skipIfNotAvailable(t, "mkfs.erofs")
	platform := templateForkE2EPlatform(t)
	if dev := templateForkE2EDevicePath(t, platform); dev != "" {
		if _, err := os.Stat(dev); err != nil {
			t.Fatalf("selected platform %q requires %s: %v", platform, dev, err)
		}
	}
	rootfsDir, rootfsImage := setupTemplateForkE2ERootfs(t)

	// The bridge and the ready server live in the private namespace of the
	// test binary. The per-child namespaces are created below it.
	seq := templateForkE2ENetworkSeq.Add(1)
	hostIP := net.IPv4(198, 18, 2, 1)
	mask := net.CIDRMask(24, 32)
	bridge := createTemplateForkE2EBridge(t, fmt.Sprintf("gvnb%x", seq), hostIP, mask,
		net.HardwareAddr{0x02, 0x18, 0x02, 0x00, byte(seq), 0x01})
	ready := newTemplateForkE2EReadyServer(t, hostIP)

	conf := templateForkE2EConf(t)
	// A network namespace for a child needs --network=sandbox.
	conf.Network = config.NetworkSandbox
	templateSpec := newReadySpec(rootfsDir, rootfsImage, hostIP.String(), ready.port, true)
	_, bundleDir, cleanup, err := testutil.SetupContainer(templateSpec, conf)
	if err != nil {
		t.Fatalf("SetupContainer(template): %v", err)
	}
	defer cleanup()
	outPath, out := openAppendTestFile(t, "template-stdout")
	errPath, errf := openAppendTestFile(t, "template-stderr")
	defer out.Close()
	defer errf.Close()
	defer logStdioOnFailure(t, outPath, errPath)
	template, err := CreateTemplate(conf, TemplateArgs{
		ID:        testutil.RandomContainerID(),
		Workers:   1,
		Spec:      templateSpec,
		BundleDir: bundleDir,
		Stdout:    out,
		Stderr:    errf,
	})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	defer DeleteTemplate(template)

	socketsBefore := socketFDCount(t)
	const children = 2
	var (
		kids    []*Container
		nets    []*forkTestNetNS
		peers   []string
		childNS []string
	)
	for i := 0; i < children; i++ {
		ns := newForkTestNetNS(t)
		hostName, peerName := fmt.Sprintf("gvnh%x%x", seq, i), fmt.Sprintf("gvnp%x%x", seq, i)
		_, peerLink := createTemplateForkE2EVeth(t, hostName, peerName, bridge)
		guestIP := net.IPv4(198, 18, 2, byte(i+2))
		ns.addPeer(t, peerLink, &net.IPNet{IP: guestIP, Mask: mask})
		if got := ns.addresses(t, peerName); len(got) != 1 {
			t.Fatalf("namespace %d: addresses of %s before fork = %v, want one", i, peerName, got)
		}

		stdoutPath, stdoutW := openAppendTestFile(t, "fork-stdout")
		stderrPath, stderrW := openAppendTestFile(t, "fork-stderr")
		defer stdoutW.Close()
		defer stderrW.Close()
		defer logStdioOnFailure(t, stdoutPath, stderrPath)
		child, err := template.Fork(conf, ForkArgs{
			ID:        testutil.RandomContainerID(),
			BundleDir: bundleDir,
			Stdout:    stdoutW,
			Stderr:    stderrW,
			NetNSPath: ns.path(),
		})
		if err != nil {
			t.Fatalf("Fork(NetNSPath) %d: %v", i, err)
		}
		// Read the child's namespace now: the guest exits as soon as it has
		// reported ready, and its /proc entry goes with it.
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", child.SandboxPid()))
		if err != nil {
			t.Fatalf("child %d: %v", i, err)
		}
		childNS = append(childNS, link)
		kids = append(kids, child)
		nets = append(nets, ns)
		peers = append(peers, peerName)
		ready.waitFor(t, guestIP)
	}

	for i := range kids {
		// The sandbox took the addresses over from the host interface.
		if got := nets[i].addresses(t, peers[i]); len(got) != 0 {
			t.Errorf("child %d: %s still has addresses %v in its namespace, want none", i, peers[i], got)
		}
		// The child runs in its own empty network namespace and has not
		// joined the namespace it got its links from.
		for j, ns := range nets {
			if childNS[i] == ns.id(t) {
				t.Errorf("child %d runs in the host-side namespace of child %d (%s)", i, j, childNS[i])
			}
		}
	}
	if childNS[0] == childNS[1] {
		t.Errorf("both children run in the network namespace %s", childNS[0])
	}

	for _, child := range kids {
		if err := child.Destroy(); err != nil {
			t.Errorf("Destroy: %v", err)
		}
	}
	// ForkNetworkArgs opens a raw socket per link in the caller. Fork must close
	// them once the child has started, or a long-lived caller leaks one per fork.
	if after := socketFDCount(t); after != socketsBefore {
		t.Errorf("open sockets: %d before the forks, %d after destroying the children", socketsBefore, after)
	}
}
