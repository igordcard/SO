# 
#   Copyright 2017 RIFT.IO Inc
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
#   Author(s): Nandan Sinha
#

import sys
import asyncio
import uuid
import abc
import functools 
from concurrent.futures import Future

from gi.repository import (RwDts as rwdts)
import rift.mano.dts as mano_dts
import rift.downloader as url_downloader
import rift.tasklets.rwlaunchpad.onboard as onboard 

if sys.version_info < (3, 4, 4): 
    asyncio.ensure_future = asyncio.async


class CopyStatusPublisher(mano_dts.DtsHandler, url_downloader.DownloaderProtocol): 

    def __init__(self, log, dts, loop, tasklet_info):
        super().__init__(log, dts, loop) 
        self.tasks = {} 
        self.tasklet_info = tasklet_info

    def xpath(self, transaction_id=None):
        return ("D,/rw-pkg-mgmt:copy-jobs/rw-pkg-mgmt:job" +
            ("[transaction-id='{}']".format(transaction_id) if transaction_id else ""))
        pass
    
    @asyncio.coroutine
    def register(self):
        self.reg = yield from self.dts.register(xpath=self.xpath(),
                  flags=rwdts.Flag.PUBLISHER|rwdts.Flag.CACHE|rwdts.Flag.NO_PREP_READ)

        assert self.reg is not None

    @asyncio.coroutine
    def register_copier(self, copier):
        copier.delegate = self
        future = self.loop.run_in_executor(None, copier.copy)
        self.tasks[copier.transaction_id] = (copier, future)

        return (copier.transaction_id, copier.dest_package_id)

    @asyncio.coroutine
    def _dts_publisher(self, job_msg): 
        # Publish the download state 
        self.reg.update_element(
                self.xpath(transaction_id=job_msg.transaction_id), job_msg) 

    @staticmethod
    def _async_add(func, fut): 
        try: 
            ret = func()
            fut.set_result(ret) 
        except Exception as e: 
            fut.set_exception(e) 

    def _schedule_dts_work(self, job_msg): 
        f = functools.partial( 
                asyncio.ensure_future, 
                self._dts_publisher(job_msg), 
                loop = self.loop)
        fut = Future()
        self.loop.call_soon_threadsafe(CopyStatusPublisher._async_add, f, fut) 
        xx = fut.result()
        if fut.exception() is not None:
            self.log.error("Caught future exception during download: %s type %s", str(fut.exception()), type(fut.exception()))
            raise fut.exception()
        return xx

    def on_download_progress(self, job_msg):
        """callback that triggers update.
        """
        return self._schedule_dts_work(job_msg) 

    def on_download_finished(self, job_msg):
        """callback that triggers update.
        """
        # clean up the local cache
        key = job_msg.transaction_id
        if key in self.tasks:
            del self.tasks[key]

        return self._schedule_dts_work(job_msg)

    def on_download_succeeded(self, job_msg): 
        """Post the catalog descriptor object to the http endpoint.
        Argument: job_msg (proto-gi descriptor_msg of the copied descriptor)

        """
        manifest = self.tasklet_info.get_pb_manifest()
        use_ssl = manifest.bootstrap_phase.rwsecurity.use_ssl
        ssl_cert, ssl_key = None, None 
        if use_ssl:
            ssl_cert = manifest.bootstrap_phase.rwsecurity.cert
            ssl_key = manifest.bootstrap_phase.rwsecurity.key

        onboarder = onboard.DescriptorOnboarder(self.log, 
                "127.0.0.1", 8008, use_ssl, ssl_cert, ssl_key)
        try:
            onboarder.onboard(job_msg)
        except onboard.OnboardError as e: 
            self.log.error("Onboard exception triggered while posting copied catalog descriptor %s", e)
            raise 


