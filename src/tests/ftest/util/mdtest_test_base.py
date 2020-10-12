#!/usr/bin/python
"""
  (C) Copyright 2020 Intel Corporation.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
  The Government's rights to use, modify, reproduce, release, perform, display,
  or disclose this software are subject to the terms of the Apache License as
  provided in Contract No. B609815.
  Any reproduction of computer software, computer software documentation, or
  portions thereof marked with this legend must also reproduce the markings.
"""
from __future__ import print_function

import re

from apricot import TestWithServers
from test_utils_pool import TestPool
from mpio_utils import MpioUtils
from mdtest_utils import MdtestCommand
from command_utils_base import CommandFailure
from test_utils_container import TestContainer
from job_manager_utils import Mpirun, Orterun
from dfuse_utils import Dfuse
from daos_utils import DaosCommand


class MdtestBase(TestWithServers):
    """Base mdtest class.

    :avocado: recursive
    """

    def __init__(self, *args, **kwargs):
        """Initialize a MdtestBase object."""
        super(MdtestBase, self).__init__(*args, **kwargs)
        self.mdtest_cmd = None
        self.processes = None
        self.hostfile_clients_slots = None
        self.dfuse = None
        self.daos_cmd = None

    def setUp(self):
        """Set up each test case."""
        # obtain separate logs
        self.update_log_file_names()
        # Start the servers and agents
        super(MdtestBase, self).setUp()

        # initialize daos_cmd
        self.daos_cmd = DaosCommand(self.bin)

        # Get the parameters for Mdtest
        self.mdtest_cmd = MdtestCommand()
        self.mdtest_cmd.get_params(self)
        self.processes = self.params.get("np", '/run/mdtest/client_processes/*')
        self.manager = self.params.get("manager", '/run/mdtest/*', "MPICH")

        self.log.info('Clients %s', self.hostlist_clients)
        self.log.info('Servers %s', self.hostlist_servers)

    def tearDown(self):
        """Tear down each test case."""
        try:
            if self.dfuse:
                self.dfuse.stop()
        finally:
            # Stop the servers and agents
            super(MdtestBase, self).tearDown()

    def create_pool(self):
        """Create a pool and execute Mdtest."""
        # Get the pool params
        self.pool = TestPool(self.context, dmg_command=self.get_dmg_command())
        self.pool.get_params(self)

        # Create a pool
        self.pool.create()

    def _create_cont(self, oclass):
        """Create a container.
        Args:
            oclass (string): Pass object class type for container create
                             explicitly.
        """

        # Get container params
        self.container = TestContainer(
            self.pool, daos_command=DaosCommand(self.bin))
        self.container.get_params(self)
        # update oclass param if specified
        if oclass:
            self.container.oclass.update(oclass)

        # create container
        self.container.create()

    def _start_dfuse(self):
        """Create a DfuseCommand object to start dfuse."""
        # Get Dfuse params

        self.dfuse = Dfuse(self.hostlist_clients, self.tmp)
        self.dfuse.get_params(self)

        # update dfuse params
        self.dfuse.set_dfuse_params(self.pool)
        self.dfuse.set_dfuse_cont_param(self.container)
        self.dfuse.set_dfuse_exports(self.server_managers[0], self.client_log)

        try:
            # start dfuse
            self.dfuse.run()
        except CommandFailure as error:
            self.log.error("Dfuse command %s failed on hosts %s",
                           str(self.dfuse), self.dfuse.hosts,
                           exc_info=error)
            self.fail("Unable to launch Dfuse.\n")

    def execute_mdtest(self, create_cont=True, oclass=None):
        """Runner method for Mdtest.
        Args:
            create_cont (bool): Create container if true
            oclass (string): Pass object class type for container create
        """
        # Create a pool if one does not already exist
        if self.pool is None:
            self.create_pool()
        # create container
        if create_cont:
            self._create_cont(oclass)
        # set Mdtest params
        self.mdtest_cmd.set_daos_params(self.server_group, self.pool)

        # start dfuse if api is POSIX
        if self.mdtest_cmd.api.value == "POSIX":
            # start dfuse
            self._start_dfuse()
            self.mdtest_cmd.test_dir.update(self.dfuse.mount_dir.value)

        # Run Mdtest
        self.run_mdtest(self.get_mdtest_job_manager_command(self.manager),
                        self.processes)
        if self.dfuse:
            self.dfuse.stop()
            self.dfuse = None

    def get_mdtest_job_manager_command(self, manager):
        """Get the MPI job manager command for Mdtest.

        Returns:
            JobManager: the object for the mpi job manager command

        """
        # Initialize MpioUtils if mdtest needs to be run using mpich
        if manager == "MPICH":
            mpio_util = MpioUtils()
            if mpio_util.mpich_installed(self.hostlist_clients) is False:
                self.fail("Exiting Test: Mpich not installed")
            return Mpirun(self.mdtest_cmd, mpitype="mpich")

        return Orterun(self.mdtest_cmd)

    def run_mdtest(self, manager, processes):
        """Run the Mdtest command.

        Args:
            manager (str): mpi job manager command
            processes (int): number of host processes
        """
        env = self.mdtest_cmd.get_default_env(str(manager), self.client_log)
        manager.assign_hosts(
            self.hostlist_clients, self.workdir, self.hostfile_clients_slots)
        manager.assign_processes(processes)
        manager.assign_environment(env)
        try:
            self.pool.display_pool_daos_space()
            manager.run()
        except CommandFailure as error:
            self.log.error("Mdtest Failed: %s", str(error))
            self.fail("Test was expected to pass but it failed.\n")
        finally:
            self.pool.display_pool_daos_space()
