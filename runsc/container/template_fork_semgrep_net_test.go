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

// Spike: send an HTTP-style request body over TCP to a forked child that runs
// an external engine on it. Reuses the e2e network pool (bridge, veth pairs,
// raw socket per child). Not part of the proposal under test.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	runscflag "gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	semnetRootfs = runscflag.String("semnet-rootfs-dir", "", "rootfs directory the EROFS image was built from")
	semnetImage  = runscflag.String("semnet-image", "", "EROFS rootfs image")
	semnetBody   = runscflag.String("semnet-body", "", "request body file")
	semnetCounts = runscflag.String("semnet-counts", "1,4,16", "comma separated child counts")
	semnetReps   = runscflag.Int("semnet-reps", 3, "repetitions per count")
	semnetPort   = runscflag.Int("semnet-port", 8080, "guest listen port")
	semnetArgs   = runscflag.String("semnet-args", "/semgrep/semgrep-core -rules /semgrep/rules.json -targets /semgrep/targets.json -json -j 1", "guest argv")
)

const semnetNetNSEnv = "GVISOR_SEMNET_NETNS"

func TestMain(m *testing.M) {
	config.RegisterFlags(runscflag.CommandLine)
	runscflag.Parse()
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v\n", err)
		os.Exit(123)
	}
	os.Exit(runTemplateForkTestsInNetNS(m, semnetNetNSEnv))
}

type semnetSample struct {
	Count, Rep       int
	NetArgsMS        float64 // createNetworkArgs (raw socket) for this child
	ForkAPIMS        float64 // Fork() returns, from the common start
	ConnectMS        float64 // first successful TCP connect to the guest, from the common start
	SendMS           float64 // writing header+body
	BodyToResultMS   float64 // connect done -> full response read (body-in to result-out)
	SendToResultMS   float64 // first body byte written -> full response read
	ForkToResultMS   float64
	Findings, Errors int
	Err              string
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func TestSemgrepNetFork(t *testing.T) {
	if *semnetRootfs == "" || *semnetImage == "" || *semnetBody == "" {
		t.Skip("set -semnet-rootfs-dir, -semnet-image and -semnet-body")
	}
	var counts []int
	maxN := 0
	for _, c := range strings.Split(*semnetCounts, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(c))
		if err != nil {
			t.Fatalf("bad count %q", c)
		}
		counts = append(counts, n)
		if n > maxN {
			maxN = n
		}
	}
	body, err := os.ReadFile(*semnetBody)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	header := []byte(fmt.Sprintf("POST /scan HTTP/1.1\r\nHost: guest\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body)))

	poolStart := time.Now()
	pool := setupTemplateForkE2ENetworkPool(t, maxN)
	fmt.Printf("SEMNET pool_setup total_ms=%.1f veths=%d per_veth_ms=%.2f (bridge + %d veth pairs + host ready server)\n",
		ms(time.Since(poolStart)), maxN, ms(time.Since(poolStart))/float64(maxN), maxN)

	conf := templateForkE2EConfForPlatform(t, "kvm")
	spec := &specs.Spec{
		Version: specs.Version,
		Root:    &specs.Root{Path: *semnetRootfs, Readonly: true},
		Process: &specs.Process{
			Args: strings.Fields(*semnetArgs),
			Env: []string{
				"PATH=/usr/local/bin:/usr/bin:/bin",
				"LD_LIBRARY_PATH=/semgrep/libs", "LD_PRELOAD=/semgrep/shim.so",
				"FORKSRV_TARGET=/scan/target.json", "FORKSRV_CHECKPOINT=1",
				fmt.Sprintf("FORKSRV_NET=%d", *semnetPort), "FORKSRV_HOLD=1",
			},
			Capabilities: specutils.AllCapabilities(),
			Cwd:          "/",
		},
		Annotations: map[string]string{
			sentryapi.RootfsPrefix + "type":    "erofs",
			sentryapi.RootfsPrefix + "source":  *semnetImage,
			sentryapi.RootfsPrefix + "overlay": config.NoOverlay.String(),
		},
	}
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("SetupContainer: %v", err)
	}
	defer cleanup()

	_, tout := openAppendTestFile(t, "template-stdout")
	_, terr := openAppendTestFile(t, "template-stderr")
	defer tout.Close()
	defer terr.Close()
	createStart := time.Now()
	template, err := CreateTemplate(conf, TemplateArgs{
		ID:        testutil.RandomContainerID(),
		Workers:   1,
		Spec:      spec,
		BundleDir: bundleDir,
		Stdout:    tout,
		Stderr:    terr,
	})
	if err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	defer DeleteTemplate(template)
	fmt.Printf("SEMNET template create_ms=%.1f pid=%d\n", ms(time.Since(createStart)), template.PID)

	// Reference: Fork() with loopback-only network args (no veth), same harness.
	for _, n := range counts {
		var lat []float64
		for rep := 0; rep < *semnetReps; rep++ {
			var wg sync.WaitGroup
			kids := make([]*Container, n)
			apis := make([]float64, n)
			start := make(chan struct{})
			outs := make([]*os.File, n)
			errs := make([]*os.File, n)
			for i := 0; i < n; i++ {
				_, outs[i] = openAppendTestFile(t, fmt.Sprintf("lb-%d-%d-%d-out", n, rep, i))
				_, errs[i] = openAppendTestFile(t, fmt.Sprintf("lb-%d-%d-%d-err", n, rep, i))
			}
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					t0 := time.Now()
					c, err := template.Fork(conf, ForkArgs{
						ID:          testutil.RandomContainerID(),
						BundleDir:   bundleDir,
						Stdout:      outs[i],
						Stderr:      errs[i],
						NetworkArgs: &sentryapi.CreateLinksAndRoutesArgs{FilePayload: urpc.FilePayload{}, LoopbackLinks: []sentryapi.LoopbackLink{sentryapi.DefaultLoopbackLink}},
					})
					apis[i] = ms(time.Since(t0))
					if err == nil {
						kids[i] = c
					}
				}(i)
			}
			close(start)
			wg.Wait()
			lat = append(lat, apis...)
			for _, c := range kids {
				if c != nil {
					c.Destroy()
				}
			}
			for i := 0; i < n; i++ {
				outs[i].Close()
				errs[i].Close()
			}
		}
		sort.Float64s(lat)
		fmt.Printf("SEMNET ref_loopback_only n=%d fork_api_ms median=%.1f p95=%.1f\n", n, lat[len(lat)/2], lat[(len(lat)*95)/100])
	}

	var all []semnetSample
	for _, n := range counts {
		for rep := 0; rep < *semnetReps; rep++ {
			all = append(all, runSemnetRound(t, pool, template, conf, bundleDir, n, rep, header, body)...)
		}
	}
	data, _ := json.MarshalIndent(all, "", " ")
	if dir := os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR"); dir != "" {
		os.WriteFile(dir+"/semnet-samples.json", data, 0644)
	}
	if p := os.Getenv("SEMNET_OUT"); p != "" {
		os.WriteFile(p, data, 0644)
	}
}

func runSemnetRound(t *testing.T, pool *templateForkE2ENetworkPool, template *Template, conf *config.Config, bundleDir string, n, rep int, header, body []byte) []semnetSample {
	samples := make([]semnetSample, n)
	kids := make([]*Container, n)
	netArgs := make([]*sentryapi.CreateLinksAndRoutesArgs, n)
	cleanups := make([]func(), n)
	outs := make([]*os.File, n)
	errs := make([]*os.File, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		netArgs[i], cleanups[i] = pool.networks[i].createNetworkArgs(t)
		samples[i].NetArgsMS = ms(time.Since(t0))
		samples[i].Count, samples[i].Rep = n, rep
		_, outs[i] = openAppendTestFile(t, fmt.Sprintf("net-%d-%d-%d-out", n, rep, i))
		_, errs[i] = openAppendTestFile(t, fmt.Sprintf("net-%d-%d-%d-err", n, rep, i))
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	var t0 time.Time
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := &samples[i]
			<-start
			c, err := template.Fork(conf, ForkArgs{
				ID:          testutil.RandomContainerID(),
				BundleDir:   bundleDir,
				Stdout:      outs[i],
				Stderr:      errs[i],
				NetworkArgs: netArgs[i],
			})
			s.ForkAPIMS = ms(time.Since(t0))
			if err != nil {
				s.Err = "fork: " + err.Error()
				return
			}
			kids[i] = c
			addr := fmt.Sprintf("%s:%d", pool.networks[i].guestIP, *semnetPort)
			var conn net.Conn
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				conn, err = net.DialTimeout("tcp4", addr, time.Second)
				if err == nil {
					break
				}
				time.Sleep(300 * time.Microsecond)
			}
			if conn == nil {
				s.Err = "connect: " + fmt.Sprint(err)
				return
			}
			defer conn.Close()
			connected := time.Now()
			s.ConnectMS = ms(connected.Sub(t0))
			conn.SetDeadline(time.Now().Add(60 * time.Second))
			sendStart := time.Now()
			if _, err := conn.Write(append(append([]byte{}, header...), body...)); err != nil {
				s.Err = "write: " + err.Error()
				return
			}
			s.SendMS = ms(time.Since(sendStart))
			var resp bytes.Buffer
			buf := make([]byte, 65536)
			for {
				k, err := conn.Read(buf)
				resp.Write(buf[:k])
				if err != nil {
					break
				}
			}
			done := time.Now()
			s.BodyToResultMS = ms(done.Sub(connected))
			s.SendToResultMS = ms(done.Sub(sendStart))
			s.ForkToResultMS = ms(done.Sub(t0))
			r := resp.Bytes()
			if i := bytes.Index(r, []byte("\r\n\r\n")); i >= 0 {
				r = r[i+4:]
			}
			if j := bytes.IndexByte(r, '{'); j >= 0 {
				var out struct {
					Results []json.RawMessage `json:"results"`
					Errors  []json.RawMessage `json:"errors"`
				}
				if err := json.Unmarshal(r[j:], &out); err == nil {
					s.Findings, s.Errors = len(out.Results), len(out.Errors)
				} else {
					s.Err = "parse: " + err.Error()
				}
			} else {
				s.Err = fmt.Sprintf("no json in %d response bytes", resp.Len())
			}
		}(i)
	}
	t0 = time.Now()
	close(start)
	wg.Wait()
	destroyStart := time.Now()
	for _, c := range kids {
		if c != nil {
			c.Destroy()
		}
	}
	destroy := ms(time.Since(destroyStart))
	for i := 0; i < n; i++ {
		cleanups[i]()
		outs[i].Close()
		errs[i].Close()
	}
	for _, s := range samples {
		fmt.Printf("SEMNET child n=%d rep=%d net_args_ms=%.2f fork_api_ms=%.1f connect_ms=%.1f send_ms=%.1f body_to_result_ms=%.1f send_to_result_ms=%.1f fork_to_result_ms=%.1f findings=%d errors=%d destroy_all_ms=%.1f err=%q\n",
			s.Count, s.Rep, s.NetArgsMS, s.ForkAPIMS, s.ConnectMS, s.SendMS, s.BodyToResultMS, s.SendToResultMS, s.ForkToResultMS, s.Findings, s.Errors, destroy, s.Err)
	}
	return samples
}
