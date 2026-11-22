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

// forkbench is a spike driver for the sandbox fork API. It boots one template
// sandbox from an EROFS image, forks N children concurrently, and reports
// per-child latencies plus the host PIDs of the template and each child so a
// script can sum PSS. It is not part of the proposal under test.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	runscflag "gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	fRunsc    = runscflag.String("fb-runsc", "", "path to runsc")
	fSidecars = runscflag.String("fb-sidecar-dir", "", "gvisor-bin directory (GVISOR_SIDECAR_BINARIES_DIR)")
	fWork     = runscflag.String("fb-work", "", "scratch directory")
	fRootfs   = runscflag.String("fb-rootfs-dir", "", "rootfs directory the EROFS image was built from")
	fImage    = runscflag.String("fb-image", "", "EROFS rootfs image")
	fCounts   = runscflag.String("fb-counts", "1,4,8,16", "comma separated child counts")
	fReps     = runscflag.Int("fb-reps", 3, "repetitions per count")
	fTarget   = runscflag.String("fb-target", "/bodies/body-16k.json", "scan target path inside the guest, passed as SCAN_TARGET")
	fArgs     = runscflag.String("fb-args", "/semgrep/semgrep-core -rules /semgrep/rules.json -targets /semgrep/targets.json -json -j 1", "guest argv, space separated")
	fEnv      = runscflag.String("fb-env", "", "extra guest env, comma separated NAME=VALUE")
	fCPUs     = runscflag.Int("fb-cpus", 1, "sandbox CPU count")
	fPlatform = runscflag.String("fb-platform", "kvm", "platform")
	fHold     = runscflag.Int("fb-hold-ms", 2000, "ms to hold children alive after the last result before sampling")
	fTimeout  = runscflag.Duration("fb-timeout", 120*time.Second, "per-child result timeout")
	fBeacon   = runscflag.String("fb-beacon", "", "if set, write a line 'phase=<name> pids=...' file for external PSS sampling")
	fWorkers  = runscflag.Int("fb-template-workers", 1, "template workers")
	fPad      = runscflag.Int("fb-pad-bytes", 0, "append PAD=<N bytes of x> to each child's ForkArgs.Env (request channel size test)")
	fProd     = runscflag.Bool("fb-production", false, "run the sandbox the production way (unprivileged user, chroot, seccomp) instead of the test-only mode")
	fMark     = runscflag.Bool("fb-mark", false, "append MARK=<child index> to each child's ForkArgs.Env (heap isolation probe)")
	fExtraEnv = runscflag.String("fb-fork-env", "", "extra ForkArgs.Env entries, comma separated NAME=VALUE")
	fNS       = runscflag.String("fb-ns", "", "if set, overrides the fork-namespaces setting: comma separated ipc, net, cgroup, or none")
	fCgParent = runscflag.String("fb-cgroup-parent", "", "if set, a cgroup v2 directory with the pids and memory controllers enabled; each child gets <dir>/<id> as ForkArgs.CgroupPath")
	fPidsMax  = runscflag.String("fb-pids-max", "", "pids.max written to each child cgroup (needs -fb-cgroup-parent)")
	fMemMax   = runscflag.String("fb-mem-max", "", "memory.max written to each child cgroup, with swap disabled (needs -fb-cgroup-parent)")
)

type childPids struct {
	ID  string `json:"id"`
	PID int    `json:"pid"`
}

type sample struct {
	Count       int     `json:"count"`
	Rep         int     `json:"rep"`
	ForkAPIMS   float64 `json:"fork_api_ms"`
	ResultMS    float64 `json:"result_ms"`
	ResumeMS    float64 `json:"guest_resume_ms"` // guest wall clock at restore return minus host T0
	ScanMS      float64 `json:"guest_scan_ms"`   // guest resume -> scan exit
	StdoutBytes int     `json:"stdout_bytes"`
	Err         string  `json:"err,omitempty"`
}

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "forkbench: %s: %v\n", what, err)
		os.Exit(1)
	}
}

func baseConf() *config.Config {
	fs := runscflag.NewFlagSet("forkbench", runscflag.ContinueOnError)
	config.RegisterFlags(fs)
	conf, err := config.NewFromFlags(fs)
	must(err, "config")
	conf.Debug = false
	conf.HostSettings = config.HostSettingsIgnore
	conf.LogPackets = false
	conf.Strace = false
	conf.Platform = *fPlatform
	conf.Network = config.NetworkNone
	conf.DirectFS = false
	conf.CPUNum = *fCPUs
	conf.TestOnlyAllowRunAsCurrentUserWithoutChroot = !*fProd
	conf.WatchdogAction = "panic"
	conf.RootDir = filepath.Join(*fWork, "root")
	if *fNS != "" {
		conf.ForkNamespaces = *fNS
	}
	return conf
}

// childCgroup creates the cgroup for child id under -fb-cgroup-parent and
// writes the requested limits. It returns "" when no cgroup parent is set.
func childCgroup(id string) string {
	if *fCgParent == "" {
		return ""
	}
	dir := filepath.Join(*fCgParent, id)
	must(os.Mkdir(dir, 0755), "mkdir cgroup "+dir)
	for file, val := range map[string]string{"pids.max": *fPidsMax, "memory.max": *fMemMax} {
		if val != "" {
			must(os.WriteFile(filepath.Join(dir, file), []byte(val), 0644), "write "+file)
		}
	}
	if *fMemMax != "" {
		// Swap would hide the memory limit.
		if err := os.WriteFile(filepath.Join(dir, "memory.swap.max"), []byte("0"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "forkbench: memory.swap.max: %v\n", err)
		}
	}
	return dir
}

// cgroupReport prints the cgroup counters of a child as one CGROUP line.
func cgroupReport(id, dir string) {
	if dir == "" {
		return
	}
	var parts []string
	for _, f := range []string{"pids.max", "pids.current", "pids.peak", "pids.events", "memory.max", "memory.current", "memory.peak", "memory.events", "cgroup.procs"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			parts = append(parts, f+"=ERR")
			continue
		}
		v := strings.Join(strings.Fields(string(b)), ",")
		if f == "cgroup.procs" {
			v = fmt.Sprintf("%d", len(strings.Fields(string(b))))
			f = "procs"
		}
		parts = append(parts, f+"="+v)
	}
	fmt.Printf("CGROUP id=%s dir=%s %s\n", id, dir, strings.Join(parts, " "))
}

func appendFile(path string) *os.File {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	must(err, "open "+path)
	return f
}

func loopbackOnly() *sentryapi.CreateLinksAndRoutesArgs {
	return &sentryapi.CreateLinksAndRoutesArgs{
		FilePayload:   urpc.FilePayload{},
		LoopbackLinks: []sentryapi.LoopbackLink{sentryapi.DefaultLoopbackLink},
	}
}

// guestTimes extracts SHIM resume=<ns> and done=<ns> lines from child stderr.
func guestTimes(stderr string) (resume, done int64) {
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "SHIM resume=") {
			resume, _ = strconv.ParseInt(strings.TrimPrefix(line, "SHIM resume="), 10, 64)
		}
		if strings.HasPrefix(line, "SHIM done=") {
			done, _ = strconv.ParseInt(strings.TrimPrefix(line, "SHIM done="), 10, 64)
		}
	}
	return
}

func main() {
	config.RegisterFlags(runscflag.CommandLine)
	runscflag.Parse()
	for name, v := range map[string]string{"-fb-runsc": *fRunsc, "-fb-work": *fWork, "-fb-rootfs-dir": *fRootfs, "-fb-image": *fImage} {
		if v == "" {
			must(fmt.Errorf("%s is required", name), "flags")
		}
	}
	specutils.ExePath = *fRunsc
	if *fSidecars != "" {
		os.Setenv("GVISOR_SIDECAR_BINARIES_DIR", *fSidecars)
	}
	must(os.MkdirAll(filepath.Join(*fWork, "root"), 0755), "mkdir root")
	conf := baseConf()

	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LD_LIBRARY_PATH=/semgrep/libs", "LD_PRELOAD=/semgrep/shim.so",
		"FORKSRV_TARGET=/scan/target.json", "FORKSRV_HOLD=1", "FORKSRV_CHECKPOINT=1"}
	if *fEnv != "" {
		env = append(env, strings.Split(*fEnv, ",")...)
	}
	spec := &specs.Spec{
		Version: specs.Version,
		Root:    &specs.Root{Path: *fRootfs, Readonly: true},
		Process: &specs.Process{
			Args:         strings.Fields(*fArgs),
			Env:          env,
			Capabilities: specutils.AllCapabilities(),
			Cwd:          "/",
		},
		Annotations: map[string]string{
			sentryapi.RootfsPrefix + "type":    "erofs",
			sentryapi.RootfsPrefix + "source":  *fImage,
			sentryapi.RootfsPrefix + "overlay": config.NoOverlay.String(),
		},
	}
	bundle := filepath.Join(*fWork, "bundle")
	must(os.MkdirAll(bundle, 0755), "mkdir bundle")
	data, err := json.Marshal(spec)
	must(err, "marshal spec")
	must(os.WriteFile(filepath.Join(bundle, "config.json"), data, 0644), "write spec")

	runDir := filepath.Join(*fWork, fmt.Sprintf("run-%d", time.Now().Unix()))
	must(os.MkdirAll(runDir, 0755), "mkdir run")
	tout, terr := appendFile(filepath.Join(runDir, "template.stdout")), appendFile(filepath.Join(runDir, "template.stderr"))

	t0 := time.Now()
	tmpl, err := container.CreateTemplate(conf, container.TemplateArgs{
		ID:        fmt.Sprintf("fb-tmpl-%d", os.Getpid()),
		Workers:   *fWorkers,
		Spec:      spec,
		BundleDir: bundle,
		PIDFile:   filepath.Join(runDir, "template.pid"),
		Stdout:    tout,
		Stderr:    terr,
	})
	must(err, "CreateTemplate")
	fmt.Printf("TEMPLATE create_ms=%.1f id=%s pid=%d platform=%s\n", ms(time.Since(t0)), tmpl.ID, tmpl.PID, tmpl.Platform)
	beacon("template", tmpl.PID, nil)
	time.Sleep(time.Duration(*fHold) * time.Millisecond)
	beacon("template-idle", tmpl.PID, nil)

	var all []sample
	for _, cs := range strings.Split(*fCounts, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(cs))
		must(err, "counts")
		for rep := 0; rep < *fReps; rep++ {
			all = append(all, runRound(conf, tmpl, runDir, n, rep)...)
		}
	}
	data, _ = json.MarshalIndent(all, "", " ")
	must(os.WriteFile(filepath.Join(runDir, "samples.json"), data, 0644), "write samples")
	fmt.Printf("SAMPLES %s\n", filepath.Join(runDir, "samples.json"))
	t1 := time.Now()
	must(tmpl.Destroy(), "template Destroy")
	fmt.Printf("TEMPLATE destroy_ms=%.1f\n", ms(time.Since(t1)))
}

// forkEnv builds the per-child ForkArgs.Env. SCAN_TARGET comes first so that a
// reader with a small buffer still sees it.
func forkEnv(i int) []string {
	env := []string{"SCAN_TARGET=" + *fTarget}
	if *fMark {
		env = append(env, fmt.Sprintf("MARK=%d", i))
	}
	if *fExtraEnv != "" {
		env = append(env, strings.Split(*fExtraEnv, ",")...)
	}
	if *fPad > 0 {
		env = append(env, "PAD="+strings.Repeat("x", *fPad))
	}
	return env
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func beacon(phase string, tmplPID int, kids []childPids) {
	line := fmt.Sprintf("phase=%s template=%d", phase, tmplPID)
	for _, k := range kids {
		line += fmt.Sprintf(" child=%d", k.PID)
	}
	for _, k := range kids {
		line += fmt.Sprintf(" cid=%s", k.ID)
	}
	line += " root=" + *fWork + "/root"
	fmt.Println("BEACON " + line)
	if *fBeacon != "" {
		os.WriteFile(*fBeacon, []byte(line+"\n"), 0644)
	}
}

func runRound(conf *config.Config, tmpl *container.Template, runDir string, n, rep int) []sample {
	samples := make([]sample, n)
	kids := make([]*container.Container, n)
	cgDirs := make([]string, n)
	pids := make([]childPids, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var hostT0 time.Time
	var t0mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("fb-%d-%d-%d-%d", os.Getpid(), n, rep, i)
			outPath := filepath.Join(runDir, id+".stdout")
			errPath := filepath.Join(runDir, id+".stderr")
			out, errf := appendFile(outPath), appendFile(errPath)
			defer out.Close()
			defer errf.Close()
			s := &samples[i]
			s.Count, s.Rep = n, rep
			<-start
			t0mu.Lock()
			t0 := hostT0
			t0mu.Unlock()
			cgDirs[i] = childCgroup(id)
			c, err := tmpl.Fork(conf, container.ForkArgs{
				ID:          id,
				Env:         forkEnv(i),
				BundleDir:   filepath.Join(*fWork, "bundle"),
				Stdout:      out,
				Stderr:      errf,
				NetworkArgs: loopbackOnly(),
				CgroupPath:  cgDirs[i],
			})
			s.ForkAPIMS = ms(time.Since(t0))
			if err != nil {
				s.Err = "fork: " + err.Error()
				return
			}
			kids[i] = c
			pids[i] = childPids{ID: id, PID: c.SandboxPid()}
			deadline := time.Now().Add(*fTimeout)
			for time.Now().Before(deadline) {
				b, _ := os.ReadFile(outPath)
				if len(b) > 0 && strings.Contains(string(b), "\"results\"") && strings.HasSuffix(strings.TrimSpace(string(b)), "}") {
					s.ResultMS = ms(time.Since(t0))
					s.StdoutBytes = len(b)
					break
				}
				time.Sleep(200 * time.Microsecond)
			}
			if s.ResultMS == 0 {
				s.Err = "timeout waiting for result"
			}
			eb, _ := os.ReadFile(errPath)
			resume, done := guestTimes(string(eb))
			if resume > 0 {
				s.ResumeMS = float64(resume-t0.UnixNano()) / 1e6
			}
			if resume > 0 && done > 0 {
				s.ScanMS = float64(done-resume) / 1e6
			}
		}(i)
	}
	t0mu.Lock()
	hostT0 = time.Now()
	t0mu.Unlock()
	close(start)
	wg.Wait()
	time.Sleep(time.Duration(*fHold) * time.Millisecond)
	var live []childPids
	for i, c := range kids {
		if c != nil {
			live = append(live, pids[i])
		}
	}
	beacon(fmt.Sprintf("children-n%d-rep%d", n, rep), tmpl.PID, live)
	// Give an external sampler time to read the beacon.
	time.Sleep(time.Duration(*fHold) * time.Millisecond)
	for i := range kids {
		if cgDirs[i] != "" {
			cgroupReport(filepath.Base(cgDirs[i]), cgDirs[i])
		}
	}
	for i, c := range kids {
		if c != nil {
			if err := c.Destroy(); err != nil {
				fmt.Fprintf(os.Stderr, "destroy: %v\n", err)
			}
		}
		if cgDirs[i] != "" {
			os.Remove(cgDirs[i])
		}
	}
	for _, s := range samples {
		fmt.Printf("CHILD n=%d rep=%d fork_api_ms=%.1f result_ms=%.1f resume_ms=%.1f scan_ms=%.1f err=%q\n", s.Count, s.Rep, s.ForkAPIMS, s.ResultMS, s.ResumeMS, s.ScanMS, s.Err)
	}
	return samples
}
