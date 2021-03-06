
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

import abc
import asyncio
import time

import numpy

from . import scaling_operation
from . import subscribers as monp_subscriber
from gi.repository import RwDts as rwdts
import rift.mano.dts as subscriber


class TimeSeries:
    """Convenience class to hold the data for the sliding window size.
    """
    def __init__(self, threshold_time):
        """
        Args:
            threshold_time (int): window size in secs
        """

        # 0 -> contains a list of all timestamps
        # 1 -> contains a list of all values.
        self._series = numpy.empty(shape=(2, 1), dtype='int64')
        self.threshold_time = threshold_time

    def add_value(self, timestamp, value):
        timestamp = int(timestamp)

        self._series = numpy.append(
                self._series,
                [[timestamp], [value]],
                axis=1)

        # Drop off stale value
        # 0 -> timestamp
        # 1 -> values
        # Get all indexes that are outside the window, and drop them
        window_values = self._series[0] >= (timestamp - self.threshold_time)
        self._series = self._series[:, window_values]

    def average(self):
        return numpy.average(self._series[1])

    def is_window_full(self):
        """Verify if there is sufficient data for the current window.
        """
        if len(self._series[0]) <= 2:
            return False

        start_time = self._series[0][0]
        end_time = self._series[0][-1]

        if (end_time - start_time) >= self.threshold_time:
            return True

        return False


class ScalingCriteria:
    class Delegate:
        """Delegate: callbacks triggered by ScalingCriteris
        """
        @abc.abstractmethod
        def threshold_out_breached(self, criteria_name, avg_value):
            """Called when the value has crossed the scale-out-threshold

            Args:
                criteria_name (str): Criteria name
                avg_value (float): The average value of the window.

            """
            pass

        @abc.abstractmethod
        def threshold_in_breached(self, criteria_name, avg_value):
            """Called when the value has drops below the scale-in-threshold

            Args:
                criteria_name (str): Criteria name
                avg_value (float): The average value of the window.

            """

            pass

    def __init__(
            self,
            log,
            dts,
            loop,
            nsr_id,
            monp_id,
            scaling_criteria,
            window_size,
            sampling_period=1,
            delegate=None):
        """
        Args:
            log : Log
            dts : DTS handle
            loop : Event Handle
            nsr_id (str): NSR ID
            monp_id (str): Monitoring parameter
            scaling_criteria : Yang data model
            window_size (int): Length of the window
            delegate : ScalingCriteria.Delegate

        Note:

        """
        self.log = log
        self.dts = dts
        self.loop = loop
        self.sampling_period = sampling_period
        self.window_size = window_size
        self.delegate = delegate
        self.nsr_id, self.monp_id = nsr_id, monp_id

        self._scaling_criteria = scaling_criteria
        self._timeseries = TimeSeries(self.window_size)
        # Flag when set, triggers scale-in request.
        self._scl_in_limit_enabled = False

        self.nsr_monp_sub = monp_subscriber.NsrMonParamSubscriber(
                self.log,
                self.dts,
                self.loop,
                self.nsr_id,
                self.monp_id,
                callback=self.add_value)

    @property
    def name(self):
        return self._scaling_criteria.name

    @property
    def scale_in(self):
        return self._scaling_criteria.scale_in_threshold

    @property
    def scale_out(self):
        return self._scaling_criteria.scale_out_threshold

    @asyncio.coroutine
    def register(self):
        yield from self.nsr_monp_sub.register()

    def deregister(self):
        self.nsr_monp_sub.deregister()

    def trigger_action(self, timestamp, avg):
        """Triggers the scale out/in

        Args:
            timestamp : time in unix epoch
            avg : Average of all the values in the window size.

        """
        if self._timeseries.average() >= self.scale_out:
            # Enable the scale in limit, only when a scale-out has happened.
            self._scl_in_limit_enabled = True
            self.delegate.threshold_out_breached(self.name, avg)

        elif self._timeseries.average() < self.scale_in and self._scl_in_limit_enabled:
            self._scl_in_limit_enabled = False
            self.delegate.threshold_in_breached(self.name, avg)


    def add_value(self, monp, action):
        """Callback from NsrMonParamSubscriber

        Args:
            monp : Yang model
            action : rwdts.QueryAction
        """
        if action == rwdts.QueryAction.DELETE:
            return

        value = monp.value_integer
        timestamp = time.time()

        self._timeseries.add_value(timestamp, value)

        if not self._timeseries.is_window_full():
            return

        if not self.delegate:
            return

        self.trigger_action(timestamp, value)


class ScalingPolicy(ScalingCriteria.Delegate):
    class Delegate:
        @abc.abstractmethod
        def scale_in(self, scaling_group_name, nsr_id):
            """Delegate called when all the criteria for scaling-in are met.

            Args:
                scaling_group_name (str): Description
                nsr_id (str): Description

            """
            pass

        @abc.abstractmethod
        def scale_out(self, scaling_group_name, nsr_id):
            """Delegate called when all the criteria for scaling-out are met.

            Args:
                scaling_group_name (str): Description
                nsr_id (str): Description
            """
            pass

    def __init__(
            self,
            log,
            dts,
            loop,
            nsr_id,
            nsd_id,
            scaling_group_name,
            scaling_policy,
            store,
            delegate=None):
        """

        Args:
            log : Log
            dts : DTS handle
            loop : Event loop
            nsr_id (str): NSR id
            nsd_id (str): NSD id
            scaling_group_name (str): Scaling group ref
            scaling_policy : Yang model
            store (SubscriberStore): Subscriber store instance
            delegate (None, optional): ScalingPolicy.Delegate
        """
        self.loop = loop
        self.log = log
        self.dts = dts
        self.nsd_id = nsd_id
        self.nsr_id = nsr_id
        self.scaling_group_name = scaling_group_name

        self._scaling_policy = scaling_policy
        self.delegate = delegate
        self.store = store

        self.monp_sub = monp_subscriber.NsrMonParamSubscriber(
                                self.log,
                                self.dts,
                                self.loop,
                                self.nsr_id,
                                callback=self.handle_nsr_monp)

        self.criteria_store = {}

        # Timestamp at which the scale-in/scale-out request was generated.
        self._last_triggered_time = None
        self.scale_in_status = {cri.name: False for cri in self.scaling_criteria}
        self.scale_out_status = {cri.name: False for cri in self.scaling_criteria}

    def get_nsd_monp_cfg(self, nsr_monp):
        """Get the NSD's mon-param config.
        """
        nsd = self.store.get_nsd(self.nsd_id)
        for monp in nsd.monitoring_param:
            if monp.id == nsr_monp.nsd_mon_param_ref:
                return monp

    def handle_nsr_monp(self, monp, action):
        """Callback for NSR mon-param handler.

        Args:
            monp : Yang Model
            action : rwdts.QueryAction
        
        """
        def handle_create():
            if monp.id in self.criteria_store:
                return

            nsd_monp = self.get_nsd_monp_cfg(monp)
            for cri in self.scaling_criteria:
                if cri.ns_monitoring_param_ref != nsd_monp.id:
                    continue

                # Create a criteria object as soon as the first monitoring data
                # is published.
                criteria = ScalingCriteria(
                        self.log,
                        self.dts,
                        self.loop,
                        self.nsr_id,
                        monp.id,
                        cri,
                        self.threshold_time,  # window size
                        delegate=self)

                self.criteria_store[monp.id] = criteria

                @asyncio.coroutine
                def task():
                    yield from criteria.register()

                self.loop.create_task(task())

        def handle_delete():
            if monp.id in self.criteria_store:
                self.criteria_store[monp.id].deregister()
                del self.criteria_store[monp.id]

        if action in [rwdts.QueryAction.CREATE, rwdts.QueryAction.UPDATE]:
            handle_create()
        elif action == rwdts.QueryAction.DELETE:
            handle_delete()


    @property
    def scaling_criteria(self):
        return self._scaling_policy.scaling_criteria

    @property
    def scale_in_op(self):
        optype = self._scaling_policy.scale_in_operation_type
        return scaling_operation.get_operation(optype)

    @property
    def scale_out_op(self):
        optype = self._scaling_policy.scale_out_operation_type
        return scaling_operation.get_operation(optype)

    @property
    def name(self):
        return self._scaling_policy.name

    @property
    def threshold_time(self):
        return self._scaling_policy.threshold_time

    @property
    def cooldown_time(self):
        return self._scaling_policy.cooldown_time

    @asyncio.coroutine
    def register(self):
        yield from self.monp_sub.register()

    def deregister(self):
        self.monp_sub.deregister()

    def _is_in_cooldown(self):
        """Verify if the current policy is in cooldown.
        """
        if not self._last_triggered_time:
            return False

        if (time.time() - self._last_triggered_time) >= self.cooldown_time:
            return False

        return True

    def threshold_in_breached(self, criteria_name, value):
        """Delegate callback when scale-in threshold is breached

        Args:
            criteria_name : Criteria name
            value : Average value
        """
        if self._is_in_cooldown():
            return

        self.scale_in_status[criteria_name] = True

        statuses = self.scale_in_status.values()
        is_breached = self.scale_in_op(statuses)

        if is_breached and self.delegate:
            self._last_triggered_time = time.time()
            # Reset all statuses
            self.scale_in_status = {cri.name: False for cri in self.scaling_criteria}
            self.delegate.scale_in(self.scaling_group_name, self.nsr_id)

    def threshold_out_breached(self, criteria_name, value):
        """Delegate callback when scale-out threshold is breached.
        Args:
            criteria_name : Criteria name
            value : Average value
        """
        if self._is_in_cooldown():
            return

        self.scale_out_status[criteria_name] = True

        statuses = self.scale_out_status.values()
        is_breached = self.scale_out_op(statuses)

        if is_breached and self.delegate:
            self._last_triggered_time = time.time()
            # Reset all statuses
            self.scale_out_status = {cri.name: False for cri in self.scaling_criteria}
            self.delegate.scale_out(self.scaling_group_name, self.nsr_id)
