
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

set(PKG_NAME rwcal-aws)
set(PKG_VERSION 1.0)
set(PKG_RELEASE 1)
set(PKG_LONG_NAME ${PKG_NAME}-${PKG_VERSION})

rift_install_python_plugin(rwcal_aws rwcal_aws.py)

rift_python_install_tree(
  FILES
    rift/rwcal/aws/__init__.py
    rift/rwcal/aws/aws_table.py
    rift/rwcal/aws/aws_drv.py
    rift/rwcal/aws/exceptions.py
    rift/rwcal/aws/prepare_vm.py
    rift/rwcal/aws/delete_vm.py
  PYTHON3_ONLY
  COMPONENT ${PKG_LONG_NAME})

