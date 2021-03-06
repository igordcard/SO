"""
# 
#   Copyright 2016 RIFT.IO Inc
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

@file rwmonparam.py
@author Varun Prasad (varun.prasad@riftio.com)
@date 01-Jul-2016

"""

import asyncio

import gi
gi.require_version('RwDts', '1.0')
gi.require_version('RwLaunchpadYang', '1.0')

from gi.repository import (
        RwDts as rwdts,
        RwLaunchpadYang,
        ProtobufC)
import rift.mano.cloud
import rift.mano.dts as subscriber
import rift.tasklets

from . import vnfr_core
from . import nsr_core


class MonitoringParameterTasklet(rift.tasklets.Tasklet):
    """The main task of this Tasklet is to listen for VNFR changes and once the
    VNFR hits the running state, triggers the monitor.
    """
    def __init__(self, *args, **kwargs):
        try:
            super().__init__(*args, **kwargs)
            self.rwlog.set_category("rw-monitor-log")
        except Exception as e:
            self.log.exception(e)

        self.vnfr_subscriber = None
        self.store = None

        self.vnfr_monitors = {}
        self.nsr_monitors = {}

        # Needs to be moved to store once the DTS bug is resolved
        self.vnfrs = {}

    def start(self):
        super().start()

        self.log.info("Starting MonitoringParameterTasklet")
        self.log.debug("Registering with dts")

        self.dts = rift.tasklets.DTS(
                self.tasklet_info,
                RwLaunchpadYang.get_schema(),
                self.loop,
                self.on_dts_state_change
                )

        self.vnfr_subscriber = subscriber.VnfrCatalogSubscriber.from_tasklet(
                self,
                callback=self.handle_vnfr)
        self.nsr_subsriber = subscriber.NsrCatalogSubscriber.from_tasklet(
                self,
                callback=self.handle_nsr)

        self.store = subscriber.SubscriberStore.from_tasklet(self)

        self.log.debug("Created DTS Api GI Object: %s", self.dts)

    def stop(self):
      try:
          self.dts.deinit()
      except Exception as e:
          self.log.exception(e)

    @asyncio.coroutine
    def init(self):
        self.log.debug("creating vnfr subscriber")
        yield from self.store.register()
        yield from self.vnfr_subscriber.register()
        yield from self.nsr_subsriber.register()

    @asyncio.coroutine
    def run(self):
        pass

    @asyncio.coroutine
    def on_dts_state_change(self, state):
        """Handle DTS state change

        Take action according to current DTS state to transition application
        into the corresponding application state

        Arguments
            state - current dts state

        """
        switch = {
            rwdts.State.INIT: rwdts.State.REGN_COMPLETE,
            rwdts.State.CONFIG: rwdts.State.RUN,
        }

        handlers = {
            rwdts.State.INIT: self.init,
            rwdts.State.RUN: self.run,
        }

        # Transition application to next state
        handler = handlers.get(state, None)
        if handler is not None:
            yield from handler()

        # Transition dts to next state
        next_state = switch.get(state, None)
        if next_state is not None:
            self.dts.handle.set_state(next_state)

    def handle_vnfr(self, vnfr, action):
        """Starts a monitoring parameter job for every VNFR that reaches
        running state

        Args:
            vnfr (GiOBject): VNFR Gi object message from DTS
            delete_mode (bool, optional): if set, stops and removes the monitor.
        """

        def vnfr_create():
            # if vnfr.operational_status == "running" and vnfr.id not in self.vnfr_monitors:
            if vnfr.config_status == "configured" and vnfr.id not in self.vnfr_monitors:

                vnf_mon = vnfr_core.VnfMonitorDtsHandler.from_vnf_data(
                        self,
                        vnfr,
                        self.store.get_vnfd(vnfr.vnfd.id))

                self.vnfr_monitors[vnfr.id] = vnf_mon
                self.vnfrs[vnfr.id] = vnfr

                @asyncio.coroutine
                def task():
                    yield from vnf_mon.register()
                    vnf_mon.start()

                self.loop.create_task(task())


        def vnfr_delete():
            if vnfr.id in self.vnfr_monitors:
                self.log.debug("VNFR %s deleted: Stopping vnfr monitoring", vnfr.id)
                vnf_mon = self.vnfr_monitors.pop(vnfr.id)
                vnf_mon.stop()
                self.vnfrs.pop(vnfr.id)

        if action in [rwdts.QueryAction.CREATE, rwdts.QueryAction.UPDATE]:
            vnfr_create()
        elif action == rwdts.QueryAction.DELETE:
            vnfr_delete()


    def handle_nsr(self, nsr, action):
        """Callback for NSR opdata changes. Creates a publisher for every
        NS that moves to config state.

        Args:
            nsr (RwNsrYang.YangData_Nsr_NsInstanceOpdata_Nsr): Ns Opdata
            action (rwdts.QueryAction): Action type of the change.
        """
        def nsr_create():
            # if nsr.operational_status == "running" and nsr.ns_instance_config_ref not in self.nsr_monitors:
            if nsr.config_status == "configured" and nsr.ns_instance_config_ref not in self.nsr_monitors:
                nsr_mon = nsr_core.NsrMonitorDtsHandler(
                        self.log,
                        self.dts,
                        self.loop,
                        nsr,
                        list(self.vnfrs.values()),
                        self.store
                        )

                self.nsr_monitors[nsr.ns_instance_config_ref] = nsr_mon

                @asyncio.coroutine
                def task():
                    yield from nsr_mon.register()
                    yield from nsr_mon.start()

                self.loop.create_task(task())



        def nsr_delete():
            if nsr.ns_instance_config_ref in self.nsr_monitors:
            # if vnfr.operational_status == "running" and vnfr.id in self.vnfr_monitors:
                nsr_mon = self.nsr_monitors.pop(nsr.ns_instance_config_ref)
                nsr_mon.stop()

        if action in [rwdts.QueryAction.CREATE, rwdts.QueryAction.UPDATE]:
            nsr_create()
        elif action == rwdts.QueryAction.DELETE:
            nsr_delete()
