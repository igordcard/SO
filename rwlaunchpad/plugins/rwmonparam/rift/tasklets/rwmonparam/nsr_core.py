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

@file nsr_core.py
@author Varun Prasad (varun.prasad@riftio.com)
@date 09-Jul-2016

"""

import asyncio
import functools
import uuid

from gi.repository import (RwDts as rwdts, NsrYang)
import rift.mano.dts as mano_dts

from . import aggregator as aggregator


class MissingValueField(Exception):
    pass


class VnfrMonitoringParamSubscriber(mano_dts.AbstractOpdataSubscriber):
    """Registers for VNFR monitoring parameter changes.
    
    Attributes:
        monp_id (str): Monitoring Param ID
        vnfr_id (str): VNFR ID
    """
    def __init__(self, log, dts, loop, vnfr_id, monp_id, callback=None):
        super().__init__(log, dts, loop, callback)
        self.vnfr_id = vnfr_id
        self.monp_id = monp_id

    def get_xpath(self):
        return("D,/vnfr:vnfr-catalog" +
               "/vnfr:vnfr[vnfr:id='{}']".format(self.vnfr_id) +
               "/vnfr:monitoring-param" +
               "[vnfr:id='{}']".format(self.monp_id))


class NsrMonitoringParam():
    """Class that handles NS Mon-param data.
    """
    MonParamMsg = NsrYang.YangData_Nsr_NsInstanceOpdata_Nsr_MonitoringParam
    MISSING = None
    DEFAULT_AGGREGATION_TYPE = "AVERAGE"

    @classmethod
    def create_nsr_mon_params(cls, nsd, constituent_vnfrs, store):
        """Convenience class that constructs NSMonitoringParam objects
        
        Args:
            nsd (RwNsdYang.YangData_Nsd_NsdCatalog_Nsd): Nsd object
            constituent_vnfrs (list): List of constituent vnfr objects of NSR
            store (SubscriberStore): Store object instance
        
        Returns:
            list NsrMonitoringParam object.

        Also handles legacy NSD descriptor which has no mon-param defines. In
        such cases the mon-params are created from VNFD's mon-param config.
        """
        MonParamMsg = NsrYang.YangData_Nsr_NsInstanceOpdata_Nsr_MonitoringParam

        mon_params = []
        for mon_param_msg in nsd.monitoring_param:
            mon_params.append(NsrMonitoringParam(
                    mon_param_msg,
                    constituent_vnfrs
                    ))

        # Legacy Handling.
        # This indicates that the NSD had no mon-param config.
        if not nsd.monitoring_param:
            for vnfr in constituent_vnfrs:
                vnfd = store.get_vnfd(vnfr.vnfd.id)
                for monp in vnfd.monitoring_param:
                    mon_params.append(NsrMonitoringParam(
                        monp,
                        [vnfr],
                        is_legacy=True))

        return mon_params

    def __init__(self, monp_config, constituent_vnfrs, is_legacy=False):
        """
        Args:
            monp_config (GiObject): Config data to create the NSR mon-param msg
            constituent_vnfrs (list): List of VNFRs that may contain the mon-param
            is_legacy (bool, optional): If set then the mon-param are created from
                vnfd's config and not NSD's config.
        """
        self._constituent_vnfr_map = {vnfr.id:vnfr for vnfr in constituent_vnfrs}

        # An internal store to hold the data
        # Key => (vnfr_id, monp_id)
        # value => (value_type, value)
        self.vnfr_monparams = {}

        # create_nsr_mon_params() is already validating for 'is_legacy' by checking if
        # nsd is having 'monitoring_param'. So removing 'self.aggregation_type is None' check for is_legacy.
        self.is_legacy = is_legacy

        if not is_legacy:
            self._msg = self._convert_nsd_msg(monp_config)
        else:
            self._msg = self._convert_vnfd_msg(monp_config)

    @property
    def nsr_mon_param_msg(self):
        """Gi object msg"""
        return self._msg

    @property
    def vnfr_ids(self):
        """Store Keys"""
        return list(self.vnfr_monparams.keys())

    @property
    def vnfr_values(self):
        """Store values"""
        return list(self.vnfr_monparams.values())

    @property
    def is_ready(self):
        """Flag which indicates if all of the constituent vnfr values are
        available to perform the aggregation"""
        return (self.MISSING not in self.vnfr_values)

    @property
    def aggregation_type(self):
        """Aggregation type"""
        return self.nsr_mon_param_msg.aggregation_type

    # @property
    # def is_legacy(self):
    #     return (self.aggregation_type is None)

    @classmethod
    def extract_value(cls, monp):
        """Class method to extract the value type and value from the 
        mon-param gi message
        
        Args:
            monp (GiObject): Mon param msg
        
        Returns:
            Tuple: (value type, value)
        
        Raises:
            MissingValueField: Raised if no valid field are available.
        """
        if monp.has_field("value_integer"):
            return ("value_integer", monp.value_integer)
        elif monp.has_field("value_decimal"):
            return ("value_decimal", monp.value_decimal)
        elif monp.has_field("value_string"):
            return ("value_string", monp.value_string)

        return None

    def _constituent_vnfrs(self, constituent_vnfr_ids):
        # Fetch the VNFRs
        vnfr_map = {}
        for constituent_vnfr in constituent_vnfr_ids:
            vnfr_id = constituent_vnfr.vnfr_id
            vnfr_map[vnfr_id] = self._store.get_vnfr(vnfr_id)

        return vnfr_map

    def _extract_ui_elements(self, monp):
        ui_fields = ["group_tag", "description", "widget_type", "units", "value_type"]
        ui_data = [getattr(monp, ui_field) for ui_field in ui_fields]

        return dict(zip(ui_fields, ui_data))


    def _convert_nsd_msg(self, nsd_monp):
        """Create initial msg without values"""
        vnfd_to_vnfr = {vnfr.vnfd.id: vnfr_id
                for vnfr_id, vnfr in self._constituent_vnfr_map.items()}

        # First, convert the monp param ref from vnfd to vnfr terms.
        vnfr_mon_param_ref = []
        for vnfd_mon in nsd_monp.vnfd_monitoring_param:
            vnfr_id = vnfd_to_vnfr[vnfd_mon.vnfd_id_ref]
            monp_id = vnfd_mon.vnfd_monitoring_param_ref

            self.vnfr_monparams[(vnfr_id, monp_id)] = self.MISSING

            vnfr_mon_param_ref.append({
                'vnfr_id_ref': vnfr_id,
                'vnfr_mon_param_ref': monp_id
                })

        monp_fields = {
                # For now both the NSD and NSR's monp ID are same.
                'id': nsd_monp.id,
                'name': nsd_monp.name,
                'nsd_mon_param_ref': nsd_monp.id,
                'vnfr_mon_param_ref': vnfr_mon_param_ref,
                'aggregation_type': nsd_monp.aggregation_type
            }

        ui_fields = self._extract_ui_elements(nsd_monp)
        monp_fields.update(ui_fields)
        monp = self.MonParamMsg.from_dict(monp_fields)

        return monp

    def _convert_vnfd_msg(self, vnfd_monp):

        vnfr = list(self._constituent_vnfr_map.values())[0]
        self.vnfr_monparams[(vnfr.id, vnfd_monp.id)] = self.MISSING

        monp_data = {
                'id': str(uuid.uuid1()),
                'name': vnfd_monp.name,
                'vnfr_mon_param_ref': [{
                    'vnfr_id_ref': vnfr.id,
                    'vnfr_mon_param_ref': vnfd_monp.id
                    }]
                }

        ui_fields = self._extract_ui_elements(vnfd_monp)
        monp_data.update(ui_fields)
        monp = self.MonParamMsg.from_dict(monp_data)

        return monp

    def update_vnfr_value(self, key, value):
        """Update the internal store

        Args:
            key (Tuple): (vnfr_id, monp_id)
            value (Tuple): (value_type, value)
        """
        self.vnfr_monparams[key] = value

    def update_ns_value(self, value_field, value):
        """Updates the NS mon-param data with the aggregated value.

        Args:
            value_field (str): Value field in NSR
            value : Aggregated value
        """
        setattr(self.nsr_mon_param_msg, value_field, value)


class NsrMonitoringParamPoller(mano_dts.DtsHandler):
    """Handler responsible for publishing NS level monitoring
    parameters.

    Design:
        1. Created subscribers for each vnfr's monitoring parameter
        2. Accumulates the VNFR's value into the NsrMonitoringParam's internal
            store.
        3. Once all values are available, aggregate the value and triggers
            callback notification to the subscribers.
    """
    @classmethod
    def from_handler(cls, handler, monp, callback):
        """Convenience class to build NsrMonitoringParamPoller object.
        """
        return cls(handler.log, handler.dts, handler.loop, monp, callback)

    def __init__(self, log, dts, loop, monp, callback=None):
        """
        Args:
            monp (NsrMonitoringParam): Param object
            callback (None, optional): Callback to be triggered after value has
                been aggregated.
        """
        super().__init__(log, dts, loop)

        self.monp = monp
        self.subscribers = []
        self.callback = callback
        self._agg = None

    def make_aggregator(self, field_types):
        if not self._agg:
            self._agg = aggregator.make_aggregator(field_types)
        return self._agg


    def update_value(self, monp, action, vnfr_id):
        """Callback that gets triggered when VNFR's mon param changes.

        Args:
            monp (Gi Object): Gi object msg
            action (rwdts.QueryAction)): Action type
            vnfr_id (str): Vnfr ID
        """
        key = (vnfr_id, monp.id)
        value = NsrMonitoringParam.extract_value(monp)

        if not value:
            return

        # Accumulate the value
        self.monp.update_vnfr_value(key, value)

        # If all values are not available, then don't start
        # the aggregation process.
        if not self.monp.is_ready:
            return

        if self.monp.is_legacy:
            # If no monp are specified then copy over the vnfr's monp data
            value_field, value = value
        else:
            field_types, values = zip(*self.monp.vnfr_values)

            value_field, value = self.make_aggregator(field_types).aggregate(
                    self.monp.aggregation_type,
                    values)

        self.monp.update_ns_value(value_field, value)
        if self.callback:
            self.callback(self.monp.nsr_mon_param_msg)

    @asyncio.coroutine
    def register(self):
        for vnfr_id, monp_id in self.monp.vnfr_ids:
            callback = functools.partial(self.update_value, vnfr_id=vnfr_id)
            self.subscribers.append(VnfrMonitoringParamSubscriber(
                self.loop, self.dts, self.loop, vnfr_id, monp_id, callback=callback))

    @asyncio.coroutine
    def start(self):
        for sub in self.subscribers:
            yield from sub.register()

    def stop(self):
        for sub in self.subscribers:
            sub.deregister()


class NsrMonitorDtsHandler(mano_dts.DtsHandler):
    """ NSR monitoring class """

    def __init__(self, log, dts, loop, nsr, constituent_vnfrs, store):
        """
        Args:
            nsr (RwNsrYang.YangData_Nsr_NsInstanceOpdata_Nsr): NSR object
            constituent_vnfrs (list): list of VNFRs in NSR
            store (SubscriberStore): Store instance
        """
        super().__init__(log, dts, loop)

        self.nsr = nsr
        self.store = store
        self.constituent_vnfrs = constituent_vnfrs
        self.mon_params_pollers = []

    def xpath(self, param_id=None):
        return ("D,/nsr:ns-instance-opdata/nsr:nsr" +
            "[nsr:ns-instance-config-ref='{}']".format(self.nsr.ns_instance_config_ref) +
            "/nsr:monitoring-param" +
            ("[nsr:id='{}']".format(param_id) if param_id else ""))

    @asyncio.coroutine
    def register(self):
        self.reg = yield from self.dts.register(xpath=self.xpath(),
                  flags=rwdts.Flag.PUBLISHER|rwdts.Flag.CACHE|rwdts.Flag.NO_PREP_READ)

        assert self.reg is not None

    def callback(self, nsr_mon_param_msg):
        """Callback that triggers update.
        """
        self.reg.update_element(
                self.xpath(param_id=nsr_mon_param_msg.id),
                nsr_mon_param_msg)

    @asyncio.coroutine
    def start(self):
        nsd = self.store.get_nsd(self.nsr.nsd_ref)
        mon_params = NsrMonitoringParam.create_nsr_mon_params(
                nsd,
                self.constituent_vnfrs,
                self.store)

        for monp in mon_params:
            poller = NsrMonitoringParamPoller.from_handler(
                    self,
                    monp,
                    callback=self.callback)

            self.mon_params_pollers.append(poller)
            yield from poller.register()
            yield from poller.start()

    def stop(self):
        self.deregister()
        for poller in self.mon_params_pollers:
            poller.stop()


    def deregister(self):
        """ de-register with dts """
        if self.reg is not None:
            self.reg.deregister()
            self.reg = None
