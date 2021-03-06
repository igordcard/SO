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
# Author(s): Austin Cormier
# Creation Date: 05/15/2015
# 

include(rift_plugin)

set(TASKLET_NAME rwnsmtasklet)

##
# This function creates an install target for the plugin artifacts
##
rift_install_python_plugin(${TASKLET_NAME} ${TASKLET_NAME}.py)

# Workaround RIFT-6485 - rpmbuild defaults to python2 for
# anything not in a site-packages directory so we have to
# install the plugin implementation in site-packages and then
# import it from the actual plugin.
rift_python_install_tree(
  FILES
    rift/tasklets/${TASKLET_NAME}/__init__.py
    rift/tasklets/${TASKLET_NAME}/${TASKLET_NAME}.py
    rift/tasklets/${TASKLET_NAME}/rwnsm_conman.py
    rift/tasklets/${TASKLET_NAME}/rwnsmplugin.py
    rift/tasklets/${TASKLET_NAME}/openmano_nsm.py
    rift/tasklets/${TASKLET_NAME}/cloud.py
    rift/tasklets/${TASKLET_NAME}/config_value_pool.py
    rift/tasklets/${TASKLET_NAME}/publisher.py
    rift/tasklets/${TASKLET_NAME}/xpath.py
    rift/tasklets/${TASKLET_NAME}/rwvnffgmgr.py
    rift/tasklets/${TASKLET_NAME}/scale_group.py
  COMPONENT ${PKG_LONG_NAME}
  PYTHON3_ONLY)
