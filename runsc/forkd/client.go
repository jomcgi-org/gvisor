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
	"sync"
	"sync/atomic"
)

// Client talks to forkd over one connection. It is safe for concurrent use,
// but the calls run one at a time; open one Client per blocking call that must
// overlap with others.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	seq  atomic.Uint64
}

// Dial connects to the socket of a forkd.
func Dial(path string) (*Client, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Do sends req and returns the response. A response with ok=false is returned
// as an *Error.
func (c *Client) Do(req *Request) (*Response, error) {
	req.Version = ProtocolVersion
	if req.ID == "" {
		req.ID = fmt.Sprintf("c%d", c.seq.Add(1))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := WriteMessage(c.conn, req); err != nil {
		return nil, err
	}
	var resp Response
	if err := ReadMessage(c.conn, &resp); err != nil {
		return nil, err
	}
	if resp.ID != req.ID && resp.ID != "" {
		return nil, fmt.Errorf("response %q answers another request than %q", resp.ID, req.ID)
	}
	if !resp.OK {
		if resp.Error == nil {
			return &resp, fmt.Errorf("forkd failed without an error")
		}
		return &resp, resp.Error
	}
	return &resp, nil
}

// Hello returns the description of forkd.
func (c *Client) Hello() (*HelloInfo, error) {
	r, err := c.Do(&Request{Op: OpHello})
	if err != nil {
		return nil, err
	}
	return r.Hello, nil
}

// Seed boots a template.
func (c *Client) Seed(req *SeedRequest) (*SeedInfo, error) {
	r, err := c.Do(&Request{Op: OpSeed, Seed: req})
	if err != nil {
		return nil, err
	}
	return r.Seed, nil
}

// Fork forks a child.
func (c *Client) Fork(req *ForkRequest) (*ChildInfo, error) {
	r, err := c.Do(&Request{Op: OpFork, Fork: req})
	if err != nil {
		return nil, err
	}
	return r.Child, nil
}

// Wait waits for a child to exit, up to timeoutMS (negative: until it exits).
// The returned child has State "running" if the timeout expired first.
func (c *Client) Wait(childID string, timeoutMS int64) (*ChildInfo, error) {
	r, err := c.Do(&Request{Op: OpWait, Wait: &WaitRequest{ChildID: childID, TimeoutMS: timeoutMS}})
	if err != nil {
		return nil, err
	}
	return r.Child, nil
}

// DeleteChild deletes a child.
func (c *Client) DeleteChild(id string) error {
	_, err := c.Do(&Request{Op: OpDelete, Delete: &DeleteRequest{Kind: "child", ID: id}})
	return err
}

// DeleteSeed deletes a seed and its children.
func (c *Client) DeleteSeed(id string) error {
	_, err := c.Do(&Request{Op: OpDelete, Delete: &DeleteRequest{Kind: "seed", ID: id}})
	return err
}

// List returns the seeds and children.
func (c *Client) List() ([]SeedInfo, []ChildInfo, error) {
	r, err := c.Do(&Request{Op: OpList})
	if err != nil {
		return nil, nil, err
	}
	return r.Seeds, r.Children, nil
}
