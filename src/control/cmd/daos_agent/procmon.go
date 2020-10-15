//
// (C) Copyright 2020 Intel Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
// The Government's rights to use, modify, reproduce, release, perform, display,
// or disclose this software are subject to the terms of the Apache License as
// provided in Contract No. 8F-30005.
// Any reproduction of computer software, computer software documentation, or
// portions thereof marked with this legend must also reproduce the markings.

package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/daos-stack/daos/src/control/drpc"
	"github.com/daos-stack/daos/src/control/logging"
)

type procMonRequest struct {
	// Pid of the process that the request is for
	pid int32
	// Whether the message is an attach or disconnect. Uses drpc method identifiers.
	action int32
}

// NewProcMonRequest generated a procMonRequest struct for the given pid and action.
func NewProcMonRequest(Pid int32, Action int32) *procMonRequest {
	return &procMonRequest{
		pid:    Pid,
		action: Action,
	}
}

type procMonResponse struct {
	// Pid the response is coming from
	pid int32
	// Error indicating why the process "died"
	err error
}

// NewResponse generates a procMonResponse struct for the given pid. The response
// will always contain an error since clean termination on disconnect will not use
// this mechanism only improper termination will.
func NewResponse(pid int32, status error) *procMonResponse {
	return &procMonResponse{
		pid: pid,
		err: status,
	}
}

type procInfo struct {
	log       logging.Logger
	pid       int32
	ctx       context.Context
	cancelCtx func()
	response  chan *procMonResponse
}

// NewProcInfo creates a new procInfo struct for use by procMon. The context passed
// in is the top level context which a child context and cancelation routine is generated.
// The response channel is the passed in by procMon to provide a unified interface
// in procMon to handle responses.
func NewProcInfo(ctx context.Context, Log logging.Logger, Pid int32, Response chan *procMonResponse) *procInfo {
	child, cancel := context.WithCancel(ctx)
	return &procInfo{
		log:       Log,
		pid:       Pid,
		ctx:       child,
		cancelCtx: cancel,
		response:  Response,
	}
}

func getProcPidInode(pid int32) (uint64, error) {

	pidPath := fmt.Sprintf("/proc/%d", pid)
	info, err := os.Stat(pidPath)
	if err != nil {
		return 0, err
	}

	// Make sure info's underlying interface is correct.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("Underlying type of FileInfo.Sys() is not Stat_t")
	}
	return stat.Ino, nil
}

// monitorProcess is the top level interface for monitoring individual processes.
// the interface is used by procMon to kick off monitoring individual processes
// under their own child context to allow for terminating individual monitoring routines.
func (p *procInfo) monitorProcess() {

	Ino, err := getProcPidInode(p.pid)
	if err != nil {
		p.response <- NewResponse(p.pid, err)
		return
	}

	p.log.Debugf("Monitoring pid:%d\n", p.pid)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(3 * time.Second):
			newIno, newErr := getProcPidInode(p.pid)
			if newErr != nil {
				if os.IsNotExist(newErr) {
					p.response <- NewResponse(p.pid, fmt.Errorf("Pid %d terminated unexpectedly", p.pid))
				} else {
					p.response <- NewResponse(p.pid, newErr)
				}
				return
			}
			if newIno != Ino {
				p.response <- NewResponse(p.pid, fmt.Errorf("Pid %d teminated but another processes took its place %d:%d", p.pid, Ino, newIno))
				return
			}
		}
	}
}

// procMon is the top level process monitoring struct which accepts requests to
// monitor and disconnect processes. Once created it is started by passing a
// context into the startMonitoring call.
type procMon struct {
	log     logging.Logger
	ctx     context.Context
	procs   map[int32]*procInfo
	request chan *procMonRequest
}

// NewProcMon creates a new process monitor struct setting initializing the
// internal process map and the request channel.
func NewProcMon(logger logging.Logger) *procMon {
	return &procMon{
		log:     logger,
		procs:   make(map[int32]*procInfo),
		request: make(chan *procMonRequest),
	}
}

func (p *procMon) handleProcessAttach(ctx context.Context, request *procMonRequest, response chan *procMonResponse) {
	info, ok := p.procs[request.pid]

	if ok == true {
		p.log.Errorf("Attempted to monitor process %d more than once", request.pid)
		return
	}

	info = NewProcInfo(ctx, p.log, request.pid, response)

	p.procs[request.pid] = info
	go info.monitorProcess()
}

func (p *procMon) handleProcessDisconnect(request *procMonRequest) {
	info, ok := p.procs[request.pid]

	if ok != true {
		p.log.Errorf("Attempted to disconnect process %d but process is missing", request.pid)
	}

	info.cancelCtx()
	delete(p.procs, request.pid)
	p.log.Debugf("Process %d has disconnected", info.pid)
}

func (p *procMon) handleRequests(ctx context.Context) {

	response := make(chan *procMonResponse)
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-p.request:
			if request.action == drpc.MethodGetAttachInfo.ID() {
				p.handleProcessAttach(ctx, request, response)

			} else if request.action == drpc.MethodDisconnect.ID() {
				p.log.Debugf("Received request in handleRequests to disconnect pid:%d\n", request.pid)
				p.handleProcessDisconnect(request)
			}
		case resp := <-response:
			p.log.Debugf("Received response from Process %d, terminated with %s", resp.pid, resp.err)
		}
	}
}

// startMonitoring is the main driver which starts the process monitor. The
// passed in context is used to terminate all monitoring in the event of shutdown.
func (p *procMon) startMonitoring(ctx context.Context) {
	go p.handleRequests(ctx)
}
