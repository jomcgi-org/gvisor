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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"

	"golang.org/x/sys/unix"
)

type listener struct {
	net.Listener
	path string
	once sync.Once
}

func (l *listener) close() {
	l.once.Do(func() {
		l.Listener.Close()
		os.Remove(l.path)
	})
}

// Listen creates the socket with mode 0600 and starts serving in the
// background. The caller must Close the server.
func (s *Server) Listen(path string) error {
	if len(path) >= 108 {
		return fmt.Errorf("socket path %q is too long", path)
	}
	_ = os.Remove(path)
	old := unix.Umask(0177)
	l, err := net.Listen("unix", path)
	unix.Umask(old)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return err
	}
	lis := &listener{Listener: l, path: path}
	s.mu.Lock()
	s.lis = lis
	s.mu.Unlock()
	go s.accept(lis)
	return nil
}

func (s *Server) accept(lis *listener) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok || !s.peerAllowed(uc) {
			conn.Close()
			continue
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			defer conn.Close()
			s.serveConn(conn)
		}()
	}
}

// peerAllowed checks the user of the connecting process.
func (s *Server) peerAllowed(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || cerr != nil {
		return false
	}
	return slices.Contains(s.opt.AllowedUIDs, cred.Uid)
}

// serveConn answers the requests of one connection in order.
func (s *Server) serveConn(conn io.ReadWriter) {
	for {
		var req Request
		if err := ReadMessage(conn, &req); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				_ = WriteMessage(conn, &Response{Version: ProtocolVersion, Error: &Error{Code: CodeInvalidArgument, Message: err.Error()}})
			}
			return
		}
		resp := s.handle(&req)
		if err := WriteMessage(conn, resp); err != nil {
			return
		}
	}
}

// handle runs one request.
func (s *Server) handle(req *Request) *Response {
	resp := &Response{Version: ProtocolVersion, ID: req.ID}
	fail := func(oe *opError) *Response {
		resp.Error = &Error{Code: oe.code, Message: oe.msg}
		return resp
	}
	if req.Version != ProtocolVersion {
		return fail(errf(CodeInvalidArgument, "protocol version %d, this forkd speaks %d", req.Version, ProtocolVersion))
	}
	if s.isClosed() && req.Op != OpHello {
		return fail(errf(CodeUnavailable, "forkd is shutting down"))
	}
	var oe *opError
	switch req.Op {
	case OpHello:
		resp.Hello = s.hello()
	case OpSeed:
		resp.Seed, oe = s.doSeed(req.Seed)
	case OpFork:
		resp.Child, oe = s.doFork(req.Fork)
	case OpWait:
		resp.Child, oe = s.doWait(req.Wait)
	case OpDelete:
		oe = s.doDelete(req.Delete)
	case OpList:
		resp.Seeds, resp.Children = s.doList()
	default:
		oe = errf(CodeInvalidArgument, "unknown operation %q", req.Op)
	}
	if oe != nil {
		return fail(oe)
	}
	resp.OK = true
	return resp
}

func (s *Server) doDelete(req *DeleteRequest) *opError {
	if req == nil {
		return errf(CodeInvalidArgument, "delete request is missing")
	}
	switch req.Kind {
	case "child":
		return s.deleteChild(req.ID)
	case "seed":
		return s.deleteSeed(req.ID)
	default:
		return errf(CodeInvalidArgument, "kind must be child or seed")
	}
}
