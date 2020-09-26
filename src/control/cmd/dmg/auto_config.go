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
//

package main

import (
	"context"

	"github.com/daos-stack/daos/src/control/lib/control"
)

// configCmd is the struct representing the top-level config subcommand.
type configCmd struct {
	Generate configGenCmd `command:"generate" alias:"g" description:"Generate DAOS server configuration file based on discoverable hardware devices"`
}

type configGenCmd struct {
	logCmd
	cfgCmd
	ctlInvokerCmd
	hostListCmd
	NumPmem  int    `default:"1" short:"p" long:"num-pmem" description:"Minimum number of SCM (pmem) devices required per storage host in DAOS system"`
	NumNvme  int    `default:"1" short:"n" long:"num-nvme" description:"Minimum number of NVMe devices required per storage host in DAOS system"`
	NetClass string `default:"best-available" short:"c" long:"net-class" description:"Network class preferred, defaults to best available" choice:"best-available" choice:"ethernet" choice:"infiniband"`
}

// Execute is run when configGenCmd activates.
//
// Attempt Runs NVMe and SCM storage scan on all connected servers.
func (cmd *configGenCmd) Execute(_ []string) error {
	ctx := context.Background()
	req := &control.StorageScanReq{}
	req.SetHostList(cmd.hostlist)
	resp, err := control.StorageScan(ctx, cmd.ctlInvoker, req)

	if err != nil {
		return err
	}

	//	var bld strings.Builder
	//	verbose := control.PrintWithVerboseOutput(true)
	//	if err := control.PrintResponseErrors(resp, &bld); err != nil {
	//		return err
	//	}
	//	if cmd.NvmeHealth {
	//		if cmd.Verbose {
	//			cmd.log.Debug("--verbose flag ignored if --health specified")
	//		}
	//		if err := pretty.PrintNvmeHealthMap(resp.HostStorage, &bld); err != nil {
	//			return err
	//		}
	//		cmd.log.Info(bld.String())
	//
	//		return resp.Errors()
	//	}
	//	if err := control.PrintHostStorageMap(resp.HostStorage, &bld, verbose); err != nil {
	//		return err
	//	}
	//	cmd.log.Info(bld.String())
	//
	return resp.Errors()
}
