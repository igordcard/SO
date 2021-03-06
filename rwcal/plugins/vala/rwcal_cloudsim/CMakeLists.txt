
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

include(rift_plugin)

set(PKG_NAME rwcal-cloudsim)
set(PKG_VERSION 1.0)
set(PKG_RELEASE 1)
set(PKG_LONG_NAME ${PKG_NAME}-${PKG_VERSION})

rift_install_python_plugin(rwcal_cloudsim rwcal_cloudsim.py)

rift_python_install_tree(
  FILES
    rift/rwcal/cloudsim/__init__.py
    rift/rwcal/cloudsim/core.py
    rift/rwcal/cloudsim/exceptions.py
    rift/rwcal/cloudsim/image.py
    rift/rwcal/cloudsim/lvm.py
    rift/rwcal/cloudsim/lxc.py
    rift/rwcal/cloudsim/net.py
    rift/rwcal/cloudsim/shell.py
  PYTHON3_ONLY
  COMPONENT ${PKG_LONG_NAME})

