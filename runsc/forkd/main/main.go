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

// Command forkd serves seed, fork, wait, delete and list over a Unix socket
// for one caller on the host. It holds sandbox templates (seeds) of one
// digest-pinned image each and forks single-use children from them. It refuses
// to start unless the isolation settings of invariant I1 hold. See package
// forkd for the protocol.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/forkd"
	"gvisor.dev/gvisor/runsc/specutils"
)

// version identifies this forkd build. It is the version of the protocol plus
// the release string that the build stamps into runsc.
const version = "forkd/1"

var (
	fStateDir    = flag.String("forkd-state-dir", "/run/forkd", "private directory for the socket, runsc state and per-seed and per-child files")
	fSocket      = flag.String("forkd-socket", "", "socket path (default <state-dir>/forkd.sock)")
	fRunsc       = flag.String("forkd-runsc", "", "path of runsc (default ../runsc relative to forkd)")
	fSidecars    = flag.String("forkd-sidecar-dir", "", "gvisor-bin directory (default the directory of forkd, if it holds gvisor_sentry)")
	fCgroup      = flag.String("forkd-cgroup-parent", "", "cgroup v2 directory below /sys/fs/cgroup with the memory and pids controllers delegated; forkd creates one leaf per child")
	fUnlimited   = flag.Bool("forkd-allow-unlimited-children", false, "let fork requests omit their cgroup limits (tests only)")
	fMaxChildren = flag.Int("forkd-max-children", 256, "running children at most")
	fAllowUIDs   = flag.String("forkd-allow-uids", "", "comma separated UIDs that may connect (default: the UID of forkd)")
	fEnvPrefixes = flag.String("forkd-env-prefixes", "", "comma separated prefixes that fork environment names must start with, for example ATE_ACTOR_")
	fExpectRunsc = flag.String("forkd-expect-runsc-sha256", "", "refuse to start unless runsc has this SHA-256")
	fExpectSent  = flag.String("forkd-expect-sentry-sha256", "", "refuse to start unless gvisor_sentry has this SHA-256")
)

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "forkd: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	config.RegisterFlags(flag.CommandLine)
	// Defaults that fork needs. An operator can override them; the startup
	// assertions refuse the ones that break isolation.
	for name, val := range map[string]string{"platform": "kvm", "network": "sandbox", "host-settings": "ignore", "directfs": "false", "watchdog-action": "panic"} {
		if f := flag.CommandLine.Lookup(name); f != nil {
			f.DefValue = val
			_ = f.Value.Set(val)
		}
	}
	flag.Parse()
	conf, err := config.NewFromFlags(flag.CommandLine)
	if err != nil {
		die("config: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		die("%v", err)
	}
	exeDir := filepath.Dir(exe)
	runsc := *fRunsc
	if runsc == "" {
		runsc = filepath.Join(exeDir, "..", "runsc")
	}
	if _, err := os.Stat(runsc); err != nil {
		die("runsc: %v (set --forkd-runsc)", err)
	}
	sidecars := *fSidecars
	if sidecars == "" {
		sidecars = exeDir
	}
	sentry := filepath.Join(sidecars, "gvisor_sentry")
	if _, err := os.Stat(sentry); err != nil {
		die("sentry: %v (set --forkd-sidecar-dir)", err)
	}
	runscSHA, sentrySHA := forkd.FileSHA256(runsc), forkd.FileSHA256(sentry)
	for _, c := range []struct{ name, have, want string }{{"runsc", runscSHA, *fExpectRunsc}, {"gvisor_sentry", sentrySHA, *fExpectSent}} {
		if c.want != "" && !strings.EqualFold(c.have, c.want) {
			die("%s has SHA-256 %s, expected %s", c.name, c.have, c.want)
		}
	}
	specutils.ExePath = runsc
	os.Setenv("GVISOR_SIDECAR_BINARIES_DIR", sidecars)

	stateDir := *fStateDir
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		die("%v", err)
	}
	// One forkd per state directory.
	lock, err := os.OpenFile(filepath.Join(stateDir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		die("%v", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		die("another forkd holds %s: %v", stateDir, err)
	}
	conf.RootDir = filepath.Join(stateDir, "root")

	opt := forkd.Options{
		StateDir:               stateDir,
		Settings:               forkd.SettingsFromConfig(conf, *fCgroup),
		AllowUnlimitedChildren: *fUnlimited,
		MaxChildren:            *fMaxChildren,
		Version:                version,
		RunscSHA256:            runscSHA,
		SentrySHA256:           sentrySHA,
	}
	if *fEnvPrefixes != "" {
		opt.EnvPrefixes = strings.Split(*fEnvPrefixes, ",")
	}
	for _, u := range strings.Split(*fAllowUIDs, ",") {
		if u == "" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(u), 10, 32)
		if err != nil {
			die("--forkd-allow-uids: %v", err)
		}
		opt.AllowedUIDs = append(opt.AllowedUIDs, uint32(n))
	}
	srv, err := forkd.NewServer(opt, forkd.NewGVisorRuntime(conf))
	if err != nil {
		die("%v", err)
	}
	sock := *fSocket
	if sock == "" {
		sock = filepath.Join(stateDir, "forkd.sock")
	}
	if err := srv.Listen(sock); err != nil {
		die("listening on %s: %v", sock, err)
	}
	fmt.Fprintf(os.Stderr, "forkd: serving %s (platform %s, protocol %d)\n", sock, conf.Platform, forkd.ProtocolVersion)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	srv.Close()
}
