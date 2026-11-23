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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/specutils"
)

// GVisorRuntime implements Runtime with runsc/container.
type GVisorRuntime struct {
	conf *config.Config
}

// NewGVisorRuntime returns a runtime that boots templates with conf. All
// templates and children share conf.RootDir: Template.Fork requires it.
func NewGVisorRuntime(conf *config.Config) *GVisorRuntime {
	return &GVisorRuntime{conf: conf}
}

// SettingsFromConfig derives the startup assertions' input from runsc's
// config.
func SettingsFromConfig(conf *config.Config, cgroupParent string) Settings {
	var ns []string
	if parsed, err := config.ParseForkNamespaces(conf.ForkNamespaces); err == nil {
		for _, n := range parsed {
			ns = append(ns, string(n))
		}
	}
	network := "other"
	switch conf.Network {
	case config.NetworkSandbox:
		network = "sandbox"
	case config.NetworkNone:
		network = "none"
	}
	return Settings{
		TestOnlyUnsafe:  conf.TestOnlyAllowRunAsCurrentUserWithoutChroot,
		DisableSeccomp:  conf.DisableSeccomp,
		Rootless:        conf.Rootless,
		DirectFS:        conf.DirectFS,
		Platform:        conf.Platform,
		Network:         network,
		Debug:           conf.Debug || conf.Strace || conf.LogPackets,
		DebugLog:        conf.DebugLog,
		ForkNamespaces:  ns,
		KVMDevicePath:   conf.PlatformDevicePath,
		CgroupParentDir: cgroupParent,
	}
}

// Platform implements Runtime.
func (r *GVisorRuntime) Platform() string { return r.conf.Platform }

// Reset implements Runtime.
func (r *GVisorRuntime) Reset() error {
	if err := os.MkdirAll(r.conf.RootDir, 0700); err != nil {
		return err
	}
	templates, err := container.ListTemplates(r.conf.RootDir)
	if err != nil {
		return err
	}
	for i := range templates {
		// Destroying the template's stub ends its pid namespace, so its children
		// die with it.
		if err := templates[i].Destroy(); err != nil {
			return fmt.Errorf("destroying leftover template %q: %w", templates[i].ID, err)
		}
	}
	entries, err := os.ReadDir(r.conf.RootDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(r.conf.RootDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

type gvisorTemplate struct {
	conf   *config.Config
	tmpl   *container.Template
	bundle string
}

// CreateTemplate implements Runtime.
func (r *GVisorRuntime) CreateTemplate(ts TemplateSpec) (Template, error) {
	rootDir := filepath.Join(ts.Dir, "rootfs")
	bundle := filepath.Join(ts.Dir, "bundle")
	for _, d := range []string{rootDir, bundle} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, err
		}
	}
	cwd := ts.Cwd
	if cwd == "" {
		cwd = "/"
	}
	spec := &specs.Spec{
		Version: specs.Version,
		Root:    &specs.Root{Path: rootDir, Readonly: true},
		Process: &specs.Process{
			Args:            ts.Args,
			Env:             ts.Env,
			Cwd:             cwd,
			User:            specs.User{UID: ts.UID, GID: ts.GID},
			NoNewPrivileges: true,
		},
		Annotations: map[string]string{
			sentryapi.RootfsPrefix + "type":    "erofs",
			sentryapi.RootfsPrefix + "source":  ts.ImagePath,
			sentryapi.RootfsPrefix + "overlay": config.NoOverlay.String(),
		},
	}
	if ts.CgroupPath != "" {
		// runsc keeps the limits of a cgroup that already exists and sizes the
		// guest's memory from its memory.max.
		spec.Linux = &specs.Linux{CgroupsPath: ts.CgroupPath}
	}
	if !ts.DropCapabilities {
		spec.Process.Capabilities = specutils.AllCapabilities()
	}
	for _, t := range ts.Tmpfs {
		opts := []string{"mode=1777"}
		if t.SizeBytes > 0 {
			opts = append(opts, "size="+strconv.FormatUint(t.SizeBytes, 10))
		}
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: t.Path, Type: "tmpfs", Source: "tmpfs", Options: opts})
	}
	data, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), data, 0644); err != nil {
		return nil, err
	}

	conf := *r.conf
	conf.CPUNum = ts.CPUs
	tmpl, err := container.CreateTemplate(&conf, container.TemplateArgs{
		ID:        ts.ID,
		Workers:   ts.Workers,
		Spec:      spec,
		BundleDir: bundle,
		Stdout:    ts.Stdout,
		Stderr:    ts.Stderr,
	})
	if err != nil {
		return nil, err
	}
	return &gvisorTemplate{conf: &conf, tmpl: tmpl, bundle: bundle}, nil
}

func (t *gvisorTemplate) PID() int { return t.tmpl.PID }

func (t *gvisorTemplate) Destroy() error { return t.tmpl.Destroy() }

func loopbackOnly() *sentryapi.CreateLinksAndRoutesArgs {
	return &sentryapi.CreateLinksAndRoutesArgs{
		FilePayload:   urpc.FilePayload{},
		LoopbackLinks: []sentryapi.LoopbackLink{sentryapi.DefaultLoopbackLink},
	}
}

func (t *gvisorTemplate) Fork(fs ForkSpec) (Child, error) {
	args := container.ForkArgs{
		ID:         fs.ID,
		Env:        fs.Env,
		BundleDir:  t.bundle,
		Stdout:     fs.Stdout,
		Stderr:     fs.Stderr,
		CgroupPath: fs.CgroupPath,
	}
	if fs.NetNSPath != "" {
		args.NetNSPath = fs.NetNSPath
		args.DisableIPv6 = fs.DisableIPv6
	} else {
		args.NetworkArgs = loopbackOnly()
	}
	c, err := t.tmpl.Fork(t.conf, args)
	if err != nil {
		return nil, err
	}
	return &gvisorChild{c: c}, nil
}

type gvisorChild struct {
	c *container.Container
}

func (c *gvisorChild) PID() int { return c.c.SandboxPid() }

func (c *gvisorChild) Wait() (WaitStatus, error) {
	ws, err := c.c.Wait()
	if err != nil {
		return WaitStatus{}, err
	}
	if ws.Exited() {
		return WaitStatus{Exited: true, ExitCode: ws.ExitStatus()}, nil
	}
	return WaitStatus{Signal: int(ws.Signal())}, nil
}

func (c *gvisorChild) Destroy() error { return c.c.Destroy() }
