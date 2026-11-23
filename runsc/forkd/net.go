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
	"net"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// vethPrefix names the host end of every veth pair that forkd creates, so that
// a new forkd can remove the ones that a crashed one left.
const vethPrefix = "fdh"

var vethSeq atomic.Uint32

// vethNet is a network namespace that forkd created for one child, with the
// host end of a veth pair outside it.
type vethNet struct {
	// fd refers to the namespace. The namespace lives while it is open or a
	// process runs in it.
	fd       int
	hostName string
}

// path names the namespace in forkd's own process.
func (v *vethNet) path() string { return fmt.Sprintf("/proc/self/fd/%d", v.fd) }

func parseCIDR(s string) (*net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	ipnet.IP = ip
	return ipnet, nil
}

func (v *Veth) validate() error {
	if v == nil {
		return fmt.Errorf("veth must be set")
	}
	for name, cidr := range map[string]string{"host_cidr": v.HostCIDR, "guest_cidr": v.GuestCIDR} {
		if _, err := parseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid %s %q: %w", name, cidr, err)
		}
	}
	return nil
}

// createVethNet creates a namespace with the guest end of a veth pair, and the
// host end in the current namespace, both up and addressed.
func createVethNet(v *Veth) (*vethNet, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	hostAddr, _ := parseCIDR(v.HostCIDR)
	guestAddr, _ := parseCIDR(v.GuestCIDR)

	n := vethSeq.Add(1)
	hostName := fmt.Sprintf("%s%x", vethPrefix, n)
	guestName := fmt.Sprintf("fdg%x", n)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName}, PeerName: guestName}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("creating veth %s: %w", hostName, err)
	}
	cleanup := func() {
		if link, err := netlink.LinkByName(hostName); err == nil {
			_ = netlink.LinkDel(link)
		}
	}
	host, err := netlink.LinkByName(hostName)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := netlink.AddrAdd(host, &netlink.Addr{IPNet: hostAddr}); err != nil {
		cleanup()
		return nil, fmt.Errorf("adding %s to %s: %w", v.HostCIDR, hostName, err)
	}
	if err := netlink.LinkSetUp(host); err != nil {
		cleanup()
		return nil, fmt.Errorf("setting %s up: %w", hostName, err)
	}
	guest, err := netlink.LinkByName(guestName)
	if err != nil {
		cleanup()
		return nil, err
	}

	type nsResult struct {
		fd  int
		err error
	}
	created := make(chan nsResult, 1)
	moved := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		// The thread stays locked: it exits with this goroutine, so no other
		// goroutine ever runs on a thread inside the new namespace.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			created <- nsResult{err: fmt.Errorf("creating a network namespace: %w", err)}
			return
		}
		fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			created <- nsResult{err: fmt.Errorf("opening the new network namespace: %w", err)}
			return
		}
		created <- nsResult{fd: fd}
		if err := <-moved; err != nil {
			done <- err
			return
		}
		// Inside the new namespace: bring up lo and the guest end.
		link, err := netlink.LinkByName(guestName)
		if err != nil {
			done <- fmt.Errorf("finding %s in the namespace: %w", guestName, err)
			return
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: guestAddr}); err != nil {
			done <- fmt.Errorf("adding %s to %s: %w", v.GuestCIDR, guestName, err)
			return
		}
		if err := netlink.LinkSetUp(link); err != nil {
			done <- fmt.Errorf("setting %s up: %w", guestName, err)
			return
		}
		if lo, err := netlink.LinkByName("lo"); err == nil {
			_ = netlink.LinkSetUp(lo)
		}
		done <- nil
	}()
	res := <-created
	if res.err != nil {
		cleanup()
		return nil, res.err
	}
	moveErr := netlink.LinkSetNsFd(guest, res.fd)
	moved <- moveErr
	if moveErr != nil {
		<-done
		unix.Close(res.fd)
		cleanup()
		return nil, fmt.Errorf("moving %s into the namespace: %w", guestName, moveErr)
	}
	if err := <-done; err != nil {
		unix.Close(res.fd)
		cleanup()
		return nil, err
	}
	return &vethNet{fd: res.fd, hostName: hostName}, nil
}

// destroy deletes the host end, which removes the pair, and drops the
// reference to the namespace.
func (v *vethNet) destroy() {
	if v == nil {
		return
	}
	if link, err := netlink.LinkByName(v.hostName); err == nil {
		_ = netlink.LinkDel(link)
	}
	unix.Close(v.fd)
}

// removeStaleVeths deletes host ends that an earlier forkd left behind.
func removeStaleVeths() (removed int) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0
	}
	for _, l := range links {
		if strings.HasPrefix(l.Attrs().Name, vethPrefix) {
			if netlink.LinkDel(l) == nil {
				removed++
			}
		}
	}
	return removed
}
