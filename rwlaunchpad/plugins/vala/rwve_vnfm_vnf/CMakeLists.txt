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
# Author(s): Anil Gunturu
# Creation Date: 10/31/2015
# 

##
# Allow specific compiler warnings
##
rift_allow_compiler_warning(unused-but-set-variable)

set(VALA_NAME rwve_vnfm_vnf)
set(VALA_FILES ${VALA_NAME}.vala)
set(VALA_VERSION 1.0)
set(VALA_RELEASE 1)
set(VALA_LONG_NAME ${VALA_NAME}-${VALA_VERSION})
set(VALA_TYPELIB_PREFIX RwVeVnfmVnf-${VALA_VERSION})

rift_add_vala(
  ${VALA_LONG_NAME}
  VALA_FILES ${VALA_FILES}
  VALA_PACKAGES 
    rw_types-1.0 rw_log_yang-1.0 rw_schema_proto-1.0 rw_yang_pb-1.0
    rw_yang-1.0 protobuf_c-1.0 rw_keyspec-1.0 rw_log-1.0

  #VAPI_DIRS ${RIFT_SUBMODULE_BINARY_ROOT}/rwcal/plugins/yang
  #GIR_PATHS ${RIFT_SUBMODULE_BINARY_ROOT}/rwcal/plugins/yang
  GENERATE_HEADER_FILE ${VALA_NAME}.h

  GENERATE_SO_FILE lib${VALA_LONG_NAME}.so
  GENERATE_VAPI_FILE ${VALA_LONG_NAME}.vapi
  GENERATE_GIR_FILE ${VALA_TYPELIB_PREFIX}.gir
  GENERATE_TYPELIB_FILE ${VALA_TYPELIB_PREFIX}.typelib
  #DEPENDS rwcal_yang rwlog_gi rwschema_yang
  )

rift_install_vala_artifacts(
  HEADER_FILES ${VALA_NAME}.h
  SO_FILES lib${VALA_LONG_NAME}.so
  VAPI_FILES ${VALA_LONG_NAME}.vapi
  GIR_FILES ${VALA_TYPELIB_PREFIX}.gir
  TYPELIB_FILES ${VALA_TYPELIB_PREFIX}.typelib
  COMPONENT ${PKG_LONG_NAME}
  DEST_PREFIX .
  )


set(subdirs
  rwve_vnfm_vnf_rest
  )
rift_add_subdirs(SUBDIR_LIST ${subdirs})
