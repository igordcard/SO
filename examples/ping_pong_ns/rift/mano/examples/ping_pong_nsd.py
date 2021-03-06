#!/usr/bin/env python3

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


import argparse
import os
import shutil
import sys
import uuid

import gi
gi.require_version('RwYang', '1.0')
gi.require_version('RwVnfdYang', '1.0')
gi.require_version('VnfdYang', '1.0')
gi.require_version('RwNsdYang', '1.0')
gi.require_version('NsdYang', '1.0')


from gi.repository import (
    RwNsdYang,
    NsdYang,
    RwVnfdYang,
    VnfdYang,
    RwYang,
)


try:
    import rift.mano.config_data.config as config_data
except ImportError:
    # Load modules from common which are not yet installed
    path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + "../../../common/python/rift/mano")
    sys.path.append(path)

    import config_data.config as config_data


NUM_PING_INSTANCES = 1
MAX_VNF_INSTANCES_PER_NS = 10
use_epa = False
aws = False
pingcount = NUM_PING_INSTANCES
use_ping_cloud_init_file = ""
use_pong_cloud_init_file = ""

PING_USERDATA_FILE = '''#cloud-config
password: fedora
chpasswd: { expire: False }
ssh_pwauth: True
runcmd:
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, ping.service ]
  - [ systemctl, start, --no-block, ping.service ]
  - [ ifup, eth1 ]
'''

PONG_USERDATA_FILE = '''#cloud-config
password: fedora
chpasswd: { expire: False }
ssh_pwauth: True
runcmd:
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, pong.service ]
  - [ systemctl, start, --no-block, pong.service ]
  - [ ifup, eth1 ]
'''


class UnknownVNFError(Exception):
    pass


class ManoDescriptor(object):
    def __init__(self, name):
        self.name = name
        self.descriptor = None

    def write_to_file(self, module_list, outdir, output_format):
        model = RwYang.Model.create_libncx()
        for module in module_list:
            model.load_module(module)

        if output_format == 'json':
            with open('%s/%s.json' % (outdir, self.name), "w") as fh:
                fh.write(self.descriptor.to_json(model))
        elif output_format.strip() == 'xml':
            with open('%s/%s.xml' % (outdir, self.name), "w") as fh:
                fh.write(self.descriptor.to_xml_v2(model))
        elif output_format.strip() == 'yaml':
            with open('%s/%s.yaml' % (outdir, self.name), "w") as fh:
                fh.write(self.descriptor.to_yaml(model))
        else:
            raise Exception("Invalid output format for the descriptor")

    def get_json(self, module_list):
        model = RwYang.Model.create_libncx()
        for module in module_list:
            model.load_module(module)
        print(self.descriptor.to_json(model))


class VirtualNetworkFunction(ManoDescriptor):
    def __init__(self, name, instance_count=1):
        self.vnfd_catalog = None
        self.vnfd = None
        self.instance_count = instance_count
        self._placement_groups = []
        self.use_vnf_init_conf = False
        super(VirtualNetworkFunction, self).__init__(name)

    def add_placement_group(self, group):
        self._placement_groups.append(group)

    def compose(self, image_name, cloud_init="", cloud_init_file="", endpoint=None, mon_params=[],
                mon_port=8888, mgmt_port=8888, num_vlr_count=1, num_ivlr_count=1,
                num_vms=1, image_md5sum=None, mano_ut=False):
        self.descriptor = RwVnfdYang.YangData_Vnfd_VnfdCatalog()
        self.id = str(uuid.uuid1())
        vnfd = self.descriptor.vnfd.add()
        vnfd.id = self.id
        vnfd.name = self.name
        vnfd.short_name = self.name
        vnfd.vendor = 'RIFT.io'
        vnfd.logo = 'rift_logo.png'
        vnfd.description = 'This is an example RIFT.ware VNF'
        vnfd.version = '1.0'

        self.vnfd = vnfd

        if mano_ut is True:
            internal_vlds = []
            for i in range(num_ivlr_count):
                internal_vld = vnfd.internal_vld.add()
                internal_vld.id = 'ivld%s' % i
                internal_vld.name = 'fabric%s' % i
                internal_vld.short_name = 'fabric%s' % i
                internal_vld.description = 'Virtual link for internal fabric%s' % i
                internal_vld.type_yang = 'ELAN'
                internal_vlds.append(internal_vld)

        for i in range(num_vlr_count):
            cp = vnfd.connection_point.add()
            cp.type_yang = 'VPORT'
            cp.name = '%s/cp%d' % (self.name, i)

        if endpoint is not None:
            endp = VnfdYang.YangData_Vnfd_VnfdCatalog_Vnfd_HttpEndpoint(
                    path=endpoint, port=mon_port, polling_interval_secs=2
                    )
            vnfd.http_endpoint.append(endp)

        # Monitoring params
        for monp_dict in mon_params:
            monp = VnfdYang.YangData_Vnfd_VnfdCatalog_Vnfd_MonitoringParam.from_dict(monp_dict)
            monp.http_endpoint_ref = endpoint
            vnfd.monitoring_param.append(monp)


        for i in range(num_vms):
            # VDU Specification
            vdu = vnfd.vdu.add()
            vdu.id = 'iovdu_%s' % i
            vdu.name = 'iovdu_%s' % i
            vdu.count = 1
            # vdu.mgmt_vpci = '0000:00:20.0'

            # specify the VM flavor
            if use_epa:
                vdu.vm_flavor.vcpu_count = 4
                vdu.vm_flavor.memory_mb = 1024
                vdu.vm_flavor.storage_gb = 4
            else:
                vdu.vm_flavor.vcpu_count = 1
                vdu.vm_flavor.memory_mb = 512
                vdu.vm_flavor.storage_gb = 4

            # Management interface
            mgmt_intf = vnfd.mgmt_interface
            mgmt_intf.vdu_id = vdu.id
            mgmt_intf.port = mgmt_port
            mgmt_intf.dashboard_params.path = endpoint
            mgmt_intf.dashboard_params.port = mgmt_port

            if cloud_init_file and len(cloud_init_file):
                vdu.cloud_init_file = cloud_init_file
            else:
                vdu.cloud_init = cloud_init
                if aws:
                    vdu.cloud_init += "  - [ systemctl, restart, --no-block, elastic-network-interfaces.service ]\n"

            # sepcify the guest EPA
            if use_epa:
                vdu.guest_epa.trusted_execution = False
                vdu.guest_epa.mempage_size = 'LARGE'
                vdu.guest_epa.cpu_pinning_policy = 'DEDICATED'
                vdu.guest_epa.cpu_thread_pinning_policy = 'PREFER'
                vdu.guest_epa.numa_node_policy.node_cnt = 2
                vdu.guest_epa.numa_node_policy.mem_policy = 'STRICT'

                node = vdu.guest_epa.numa_node_policy.node.add()
                node.id = 0
                node.memory_mb = 512
                vcpu = node.vcpu.add()
                vcpu.id = 0
                vcpu = node.vcpu.add()
                vcpu.id = 1

                node = vdu.guest_epa.numa_node_policy.node.add()
                node.id = 1
                node.memory_mb = 512
                vcpu = node.vcpu.add()
                vcpu.id = 2
                vcpu = node.vcpu.add()
                vcpu.id = 3

                # specify the vswitch EPA
                vdu.vswitch_epa.ovs_acceleration = 'DISABLED'
                vdu.vswitch_epa.ovs_offload = 'DISABLED'

                # Specify the hypervisor EPA
                vdu.hypervisor_epa.type_yang = 'PREFER_KVM'

                # Specify the host EPA
                # vdu.host_epa.cpu_model = 'PREFER_SANDYBRIDGE'
                # vdu.host_epa.cpu_arch = 'PREFER_X86_64'
                # vdu.host_epa.cpu_vendor = 'PREFER_INTEL'
                # vdu.host_epa.cpu_socket_count = 2
                # vdu.host_epa.cpu_core_count = 8
                # vdu.host_epa.cpu_core_thread_count = 2
                # vdu.host_epa.cpu_feature = ['PREFER_AES', 'REQUIRE_VME', 'PREFER_MMX','REQUIRE_SSE2']

            if aws:
                vdu.image = 'rift-ping-pong'
            else:
                vdu.image = image_name
                if image_md5sum is not None:
                    vdu.image_checksum = image_md5sum

            if mano_ut is True:
                for i in range(num_ivlr_count):
                    internal_cp = vdu.internal_connection_point.add()
                    if vnfd.name.find("ping") >= 0:
                        cp_name = "ping"
                    else:
                        cp_name = "pong"
                    internal_cp.name = cp_name + "/icp{}".format(i)
                    internal_cp.id = cp_name + "/icp{}".format(i)
                    internal_cp.type_yang = 'VPORT'
                    ivld_cp = internal_vlds[i].internal_connection_point_ref.add()
                    ivld_cp.id_ref = internal_cp.id

                    internal_interface = vdu.internal_interface.add()
                    internal_interface.name = 'fab%d' % i
                    internal_interface.vdu_internal_connection_point_ref = internal_cp.id
                    internal_interface.virtual_interface.type_yang = 'VIRTIO'

                    # internal_interface.virtual_interface.vpci = '0000:00:1%d.0'%i

            for i in range(num_vlr_count):
                external_interface = vdu.external_interface.add()
                external_interface.name = 'eth%d' % i
                external_interface.vnfd_connection_point_ref = '%s/cp%d' % (self.name, i)
                if use_epa:
                    external_interface.virtual_interface.type_yang = 'VIRTIO'
                else:
                    external_interface.virtual_interface.type_yang = 'VIRTIO'
                # external_interface.virtual_interface.vpci = '0000:00:2%d.0'%i

        for group in self._placement_groups:
            placement_group = vnfd.placement_groups.add()
            placement_group.name = group.name
            placement_group.requirement = group.requirement
            placement_group.strategy = group.strategy
            if group.vdu_list:
                ### Add specific VDUs to placement group
                for vdu in group.vdu_list:
                    member_vdu = placement_group.member_vdus.add()
                    member_vdu.member_vdu_ref = vdu.id
            else:
                ### Add all VDUs to placement group
                for vdu in vnfd.vdu:
                    member_vdu = placement_group.member_vdus.add()
                    member_vdu.member_vdu_ref = vdu.id


    def write_to_file(self, outdir, output_format):
        dirpath = "%s/%s" % (outdir, self.name)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
        super(VirtualNetworkFunction, self).write_to_file(['vnfd', 'rw-vnfd'],
                                                          dirpath,
                                                          output_format)
        self.add_scripts(outdir)

    def add_scripts(self, outdir):
        script_dir = os.path.join(outdir, self.name, 'cloud_init')
        try:
            os.makedirs(script_dir)
        except OSError:
            if not os.path.isdir(script_dir):
                raise

        if 'ping' in self.name:
            script_file = os.path.join(script_dir, 'ping_cloud_init.cfg')
            cfg = PING_USERDATA_FILE
        else:
            script_file = os.path.join(script_dir, 'pong_cloud_init.cfg')
            cfg = PONG_USERDATA_FILE

        with open(script_file, "w") as f:
            f.write("{}".format(cfg))

        # Copy the vnf_init_config script
        if self.use_vnf_init_conf and ('ping' in self.name):
            script_name = 'ping_set_rate.py'

            src_path = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
            script_src = os.path.join(src_path, script_name)
            if not os.path.exists(script_src):
                src_path = os.path.join(os.environ['RIFT_ROOT'],
                                        'modules/core/mano/examples/ping_pong_ns/rift/mano/examples')
                script_src = os.path.join(src_path, script_name)

            dest_path = os.path.join(outdir, self.name, 'scripts')
            os.makedirs(dest_path, exist_ok=True)

            shutil.copy2(script_src, dest_path)


class NetworkService(ManoDescriptor):
    def __init__(self, name):
        super(NetworkService, self).__init__(name)
        self._scale_groups = []
        self.vnfd_config = {}
        self._placement_groups = []

    def ping_config(self, mano_ut, use_ns_init_conf, use_vnf_init_conf):
        suffix = ''
        if mano_ut:
            ping_cfg = r'''
#!/bin/bash

echo "!!!!!!!! Executed ping Configuration !!!!!!!!!"
            '''
        else:
            ping_cfg = r'''
#!/bin/bash

# Rest API config
ping_mgmt_ip='<rw_mgmt_ip>'
ping_mgmt_port=18888

# VNF specific configuration
pong_server_ip='<rw_connection_point_name pong_vnfd%s/cp0>'
ping_rate=5
server_port=5555

# Make rest API calls to configure VNF
curl -D /dev/stdout \
    -H "Accept: application/vnd.yang.data+xml" \
    -H "Content-Type: application/vnd.yang.data+json" \
    -X POST \
    -d "{\"ip\":\"$pong_server_ip\", \"port\":$server_port}" \
    http://${ping_mgmt_ip}:${ping_mgmt_port}/api/v1/ping/server
rc=$?
if [ $rc -ne 0 ]
then
    echo "Failed to set server info for ping!"
    exit $rc
fi
''' % suffix

            if use_vnf_init_conf is False:
                 ping_cfg +='''
curl -D /dev/stdout \
    -H "Accept: application/vnd.yang.data+xml" \
    -H "Content-Type: application/vnd.yang.data+json" \
    -X POST \
    -d "{\"rate\":$ping_rate}" \
    http://${ping_mgmt_ip}:${ping_mgmt_port}/api/v1/ping/rate
rc=$?
if [ $rc -ne 0 ]
then
    echo "Failed to set ping rate!"
    exit $rc
fi

'''
            if use_ns_init_conf:
                ping_cfg += "exit 0\n"
            else:
                ping_cfg +='''
output=$(curl -D /dev/stdout \
    -H "Accept: application/vnd.yang.data+xml" \
    -H "Content-Type: application/vnd.yang.data+json" \
    -X POST \
    -d "{\"enable\":true}" \
    http://${ping_mgmt_ip}:${ping_mgmt_port}/api/v1/ping/adminstatus/state)
if [[ $output == *"Internal Server Error"* ]]
then
    echo $output
    exit 3
else
    echo $output
fi

exit 0
'''
        return ping_cfg

    def pong_config(self, mano_ut, use_ns_init_conf):
        suffix = ''
        if mano_ut:
            pong_cfg = r'''
#!/bin/bash

echo "!!!!!!!! Executed pong Configuration !!!!!!!!!"
            '''
        else:
            pong_cfg = r'''
#!/bin/bash

# Rest API configuration
pong_mgmt_ip='<rw_mgmt_ip>'
pong_mgmt_port=18889
# username=<rw_username>
# password=<rw_password>

# VNF specific configuration
pong_server_ip='<rw_connection_point_name pong_vnfd%s/cp0>'
server_port=5555

# Make Rest API calls to configure VNF
curl -D /dev/stdout \
    -H "Accept: application/vnd.yang.data+xml" \
    -H "Content-Type: application/vnd.yang.data+json" \
    -X POST \
    -d "{\"ip\":\"$pong_server_ip\", \"port\":$server_port}" \
    http://${pong_mgmt_ip}:${pong_mgmt_port}/api/v1/pong/server
rc=$?
if [ $rc -ne 0 ]
then
    echo "Failed to set server(own) info for pong!"
    exit $rc
fi

''' % suffix

            if use_ns_init_conf:
                pong_cfg += "exit 0\n"
            else:
                pong_cfg +='''
curl -D /dev/stdout \
    -H "Accept: application/vnd.yang.data+xml" \
    -H "Content-Type: application/vnd.yang.data+json" \
    -X POST \
    -d "{\"enable\":true}" \
    http://${pong_mgmt_ip}:${pong_mgmt_port}/api/v1/pong/adminstatus/state
rc=$?
if [ $rc -ne 0 ]
then
    echo "Failed to enable pong service!"
    exit $rc
fi

exit 0
'''
        return pong_cfg

    def pong_fake_juju_config(self, vnf_config):

        if vnf_config:
            # Select "script" configuration
            vnf_config.juju.charm = 'clearwater-aio-proxy'

            # Set the initital-config
            vnf_config.create_initial_config_primitive()
            init_config = VnfdYang.InitialConfigPrimitive.from_dict({
                "seq": 1,
                "name": "config",
                "parameter": [
                    {"name": "proxied_ip", "value": "<rw_mgmt_ip>"},
                ]
            })
            vnf_config.initial_config_primitive.append(init_config)

            init_config_action = VnfdYang.InitialConfigPrimitive.from_dict({
                "seq": 2,
                "name": "action1",
                "parameter": [
                    {"name": "Pong Connection Point", "value": "pong_vnfd/cp0"},
                ]
            })
            vnf_config.initial_config_primitive.append(init_config_action)
            init_config_action = VnfdYang.InitialConfigPrimitive.from_dict({
                "seq": 3,
                "name": "action2",
                "parameter": [
                    {"name": "Ping Connection Point", "value": "ping_vnfd/cp0"},
                ]
            })
            vnf_config.initial_config_primitive.append(init_config_action)

            # Config parameters can be taken from config.yaml and
            # actions from actions.yaml in the charm
            # Config to set the home domain
            vnf_config.create_service_primitive()
            config = VnfdYang.ServicePrimitive.from_dict({
                "name": "config",
                "parameter": [
                    {"name": "home_domain", "data_type": "STRING"},
                    {"name": "base_number", "data_type": "STRING"},
                    {"name": "number_count", "data_type": "INTEGER"},
                    {"name": "password", "data_type": "STRING"},
                ]
            })
            vnf_config.service_primitive.append(config)

            config = VnfdYang.ServicePrimitive.from_dict({
                "name": "create-update-user",
                # "user-defined-script":"/tmp/test.py",
                "parameter": [
                    {"name": "number", "data_type": "STRING", "mandatory": True},
                    {"name": "password", "data_type": "STRING", "mandatory": True},
                ]
            })
            vnf_config.service_primitive.append(config)

            config = VnfdYang.ServicePrimitive.from_dict({
                "name": "delete-user",
                "parameter": [
                    {"name": "number", "data_type": "STRING", "mandatory": True},
                ]
            })
            vnf_config.service_primitive.append(config)

    def default_config(self, const_vnfd, vnfd, mano_ut,
                       use_ns_init_conf,
                       use_vnf_init_conf):
        vnf_config = vnfd.vnfd.vnf_configuration

        vnf_config.config_attributes.config_priority = 0
        vnf_config.config_attributes.config_delay = 0

        # Select "script" configuration
        vnf_config.script.script_type = 'bash'

        if vnfd.name == 'pong_vnfd' or vnfd.name == 'pong_vnfd_with_epa' or vnfd.name == 'pong_vnfd_aws':
            vnf_config.config_attributes.config_priority = 1
            vnf_config.config_template = self.pong_config(mano_ut, use_ns_init_conf)
            # First priority config delay will delay the entire NS config delay
            if mano_ut is False:
                vnf_config.config_attributes.config_delay = 60
            else:
                # This is PONG and inside mano_ut
                # This is test only
                vnf_config.config_attributes.config_delay = 10
                # vnf_config.config_template = self.pong_config(vnf_config, use_ns_init_conf)

        if vnfd.name == 'ping_vnfd' or vnfd.name == 'ping_vnfd_with_epa' or vnfd.name == 'ping_vnfd_aws':
            vnf_config.config_attributes.config_priority = 2
            vnf_config.config_template = self.ping_config(mano_ut,
                                                          use_ns_init_conf,
                                                          use_vnf_init_conf)
            if use_vnf_init_conf:
                vnf_config.initial_config_primitive.add().from_dict(
                    {
                        "seq": 1,
                        "name": "set ping rate",
                        "user_defined_script": "ping_set_rate.py",
                        "parameter": [
                            {
                                'name': 'rate',
                                'value': '5',
                            },
                        ],
                    }
                )

    def ns_config(self, nsd, vnfd_list, mano_ut):
        # Used by scale group
        if mano_ut:
            nsd.service_primitive.add().from_dict(
                {
                    "name": "ping config",
                    "user_defined_script": "{}".format(os.path.join(
                        os.environ['RIFT_ROOT'],
                        'modules/core/mano',
                        'examples/ping_pong_ns/rift/mano/examples',
                        'ping_config_ut.sh'))
                })
        else:
            nsd.service_primitive.add().from_dict(
                {
                    "name": "ping config",
                    "user_defined_script": "ping_config.py"
                })

    def ns_initial_config(self, nsd):
        nsd.initial_config_primitive.add().from_dict(
            {
                "seq": 1,
                "name": "start traffic",
                "user_defined_script": "start_traffic.py",
                "parameter": [
                    {
                        'name': 'userid',
                        'value': 'rift',
                    },
                ],
            }
        )

    def add_scale_group(self, scale_group):
        self._scale_groups.append(scale_group)

    def add_placement_group(self, placement_group):
        self._placement_groups.append(placement_group)

    def create_mon_params(self, vnfds):
        NsdMonParam = NsdYang.YangData_Nsd_NsdCatalog_Nsd_MonitoringParam
        param_id = 1
        for vnfd_obj in vnfds:
            for mon_param in vnfd_obj.vnfd.monitoring_param:
                nsd_monp = NsdMonParam.from_dict({
                        'id': str(param_id),
                        'name': mon_param.name,
                        'aggregation_type': "AVERAGE",
                        'value_type': mon_param.value_type,
                        'vnfd_monitoring_param': [
                                {'vnfd_id_ref': vnfd_obj.vnfd.id,
                                'vnfd_monitoring_param_ref': mon_param.id}]
                        })

                self.nsd.monitoring_param.append(nsd_monp)
                param_id += 1




    def compose(self, vnfd_list, cpgroup_list, mano_ut,
                use_ns_init_conf=True,
                use_vnf_init_conf=True,):

        if mano_ut:
            # Disable NS initial config primitive
            use_ns_init_conf = False
            use_vnf_init_conf = False

        self.descriptor = RwNsdYang.YangData_Nsd_NsdCatalog()
        self.id = str(uuid.uuid1())
        nsd = self.descriptor.nsd.add()
        self.nsd = nsd
        nsd.id = self.id
        nsd.name = self.name
        nsd.short_name = self.name
        nsd.vendor = 'RIFT.io'
        nsd.logo = 'rift_logo.png'
        nsd.description = 'Toy NS'
        nsd.version = '1.0'
        nsd.input_parameter_xpath.append(
                NsdYang.YangData_Nsd_NsdCatalog_Nsd_InputParameterXpath(
                    xpath="/nsd:nsd-catalog/nsd:nsd/nsd:vendor",
                    )
                )

        ip_profile = nsd.ip_profiles.add()
        ip_profile.name = "InterVNFLink"
        ip_profile.description  = "Inter VNF Link"
        ip_profile.ip_profile_params.ip_version = "ipv4"
        ip_profile.ip_profile_params.subnet_address = "31.31.31.0/24"
        ip_profile.ip_profile_params.gateway_address = "31.31.31.210"

        vld_id = 1
        for cpgroup in cpgroup_list:
            vld = nsd.vld.add()
            vld.id = 'ping_pong_vld%s' % vld_id
            vld_id += 1
            vld.name = 'ping_pong_vld'  # hard coded
            vld.short_name = vld.name
            vld.vendor = 'RIFT.io'
            vld.description = 'Toy VL'
            vld.version = '1.0'
            vld.type_yang = 'ELAN'
            vld.ip_profile_ref = 'InterVNFLink'
            for cp in cpgroup:
                cpref = vld.vnfd_connection_point_ref.add()
                cpref.member_vnf_index_ref = cp[0]
                cpref.vnfd_id_ref = cp[1]
                cpref.vnfd_connection_point_ref = cp[2]

        vnfd_index_map = {}
        member_vnf_index = 1
        for vnfd in vnfd_list:
            for i in range(vnfd.instance_count):
                constituent_vnfd = nsd.constituent_vnfd.add()
                constituent_vnfd.member_vnf_index = member_vnf_index
                vnfd_index_map[vnfd] = member_vnf_index

                # Set the start by default to false  for ping vnfd,
                # if scaling is enabled
                if (len(self._scale_groups) and
                    vnfd.descriptor.vnfd[0].name == 'ping_vnfd'):
                    constituent_vnfd.start_by_default = False

                constituent_vnfd.vnfd_id_ref = vnfd.descriptor.vnfd[0].id
                self.default_config(constituent_vnfd, vnfd, mano_ut,
                                    use_ns_init_conf, use_vnf_init_conf)
                member_vnf_index += 1

        # Enable config primitives if either mano_ut or
        # scale groups are enabled
        if mano_ut or len(self._scale_groups):
            self.ns_config(nsd, vnfd_list, mano_ut)

        # Add NS initial config to start traffic
        if use_ns_init_conf:
            self.ns_initial_config(nsd)

        for scale_group in self._scale_groups:
            group_desc = nsd.scaling_group_descriptor.add()
            group_desc.name = scale_group.name
            group_desc.max_instance_count = scale_group.max_count
            group_desc.min_instance_count = scale_group.min_count
            for vnfd, count in scale_group.vnfd_count_map.items():
                member = group_desc.vnfd_member.add()
                member.member_vnf_index_ref = vnfd_index_map[vnfd]
                member.count = count

            for trigger in scale_group.config_action:
                config_action = group_desc.scaling_config_action.add()
                config_action.trigger = trigger
                config = scale_group.config_action[trigger]
                config_action.ns_config_primitive_name_ref = config['ns-config-primitive-name-ref']

        for placement_group in self._placement_groups:
            group = nsd.placement_groups.add()
            group.name = placement_group.name
            group.strategy = placement_group.strategy
            group.requirement = placement_group.requirement
            for member_vnfd in placement_group.vnfd_list:
                member = group.member_vnfd.add()
                member.vnfd_id_ref = member_vnfd.descriptor.vnfd[0].id
                member.member_vnf_index_ref = vnfd_index_map[member_vnfd]

        # self.create_mon_params(vnfd_list)

    def write_config(self, outdir, vnfds):

        converter = config_data.ConfigPrimitiveConvertor()
        yaml_data = converter.extract_nsd_config(self.nsd)

        ns_config_dir = os.path.join(outdir, self.name, "ns_config")
        os.makedirs(ns_config_dir, exist_ok=True)
        vnf_config_dir = os.path.join(outdir, self.name, "vnf_config")
        os.makedirs(vnf_config_dir, exist_ok=True)

        if len(yaml_data):
            with open('%s/%s.yaml' % (ns_config_dir, self.id), "w") as fh:
                fh.write(yaml_data)

        for i, vnfd in enumerate(vnfds, start=1):
            yaml_data = converter.extract_vnfd_config(vnfd)

            if len(yaml_data):
                with open('%s/%s__%s.yaml' % (vnf_config_dir, vnfd.id, i), "w") as fh:
                    fh.write(yaml_data)

    def write_initial_config_script(self, outdir):
        script_name = 'start_traffic.py'

        src_path = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        script_src = os.path.join(src_path, script_name)
        if not os.path.exists(script_src):
            src_path = os.path.join(os.environ['RIFT_ROOT'],
            'modules/core/mano/examples/ping_pong_ns/rift/mano/examples')
            script_src = os.path.join(src_path, script_name)

        dest_path = os.path.join(outdir, 'scripts')
        os.makedirs(dest_path, exist_ok=True)

        shutil.copy2(script_src, dest_path)

    def write_to_file(self, outdir, output_format):
        dirpath = os.path.join(outdir, self.name)
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)

        super(NetworkService, self).write_to_file(["nsd", "rw-nsd"],
                                                  dirpath,
                                                  output_format)

        # Write the initial config script
        self.write_initial_config_script(dirpath)


def get_ping_mon_params(path):
    return [
            {
                'id': '1',
                'name': 'ping-request-tx-count',
                'http_endpoint_ref': path,
                'json_query_method': "NAMEKEY",
                'value_type': "INT",
                'description': 'no of ping requests',
                'group_tag': 'Group1',
                'widget_type': 'COUNTER',
                'units': 'packets'
                },

            {
                'id': '2',
                'name': 'ping-response-rx-count',
                'http_endpoint_ref': path,
                'json_query_method': "NAMEKEY",
                'value_type': "INT",
                'description': 'no of ping responses',
                'group_tag': 'Group1',
                'widget_type': 'COUNTER',
                'units': 'packets'
                },
            ]


def get_pong_mon_params(path):
    return [
            {
                'id': '1',
                'name': 'ping-request-rx-count',
                'http_endpoint_ref': path,
                'json_query_method': "NAMEKEY",
                'value_type': "INT",
                'description': 'no of ping requests',
                'group_tag': 'Group1',
                'widget_type': 'COUNTER',
                'units': 'packets'
                },

            {
                'id': '2',
                'name': 'ping-response-tx-count',
                'http_endpoint_ref': path,
                'json_query_method': "NAMEKEY",
                'value_type': "INT",
                'description': 'no of ping responses',
                'group_tag': 'Group1',
                'widget_type': 'COUNTER',
                'units': 'packets'
                },
            ]


class ScaleGroup(object):
    def __init__(self, name, min_count=1, max_count=1):
        self.name = name
        self.min_count = min_count
        self.max_count = max_count
        self.vnfd_count_map = {}
        self.config_action = {}

    def add_vnfd(self, vnfd, vnfd_count):
        self.vnfd_count_map[vnfd] = vnfd_count

    def add_config(self):
        self.config_action['post_scale_out']= {'ns-config-primitive-name-ref':
                                               'ping config'}

class PlacementGroup(object):
    def __init__(self, name):
        self.name = name
        self.strategy = ''
        self.requirement = ''

    def add_strategy(self, strategy):
        self.strategy = strategy

    def add_requirement(self, requirement):
        self.requirement = requirement

class NsdPlacementGroup(PlacementGroup):
    def __init__(self, name):
        self.vnfd_list = []
        super(NsdPlacementGroup, self).__init__(name)

    def add_member(self, vnfd):
        self.vnfd_list.append(vnfd)


class VnfdPlacementGroup(PlacementGroup):
    def __init__(self, name):
        self.vdu_list = []
        super(VnfdPlacementGroup, self).__init__(name)

    def add_member(self, vdu):
        self.vdu_list.append(vdu)




def generate_ping_pong_descriptors(fmt="json",
                                   write_to_file=False,
                                   out_dir="./",
                                   pingcount=NUM_PING_INSTANCES,
                                   external_vlr_count=1,
                                   internal_vlr_count=1,
                                   num_vnf_vms=1,
                                   ping_md5sum=None,
                                   pong_md5sum=None,
                                   mano_ut=False,
                                   use_scale_group=False,
                                   ping_fmt=None,
                                   pong_fmt=None,
                                   nsd_fmt=None,
                                   use_mon_params=True,
                                   ping_userdata=None,
                                   pong_userdata=None,
                                   ex_ping_userdata=None,
                                   ex_pong_userdata=None,
                                   use_placement_group=True,
                                   use_ns_init_conf=True,
                                   use_vnf_init_conf=True,
                                   ):
    # List of connection point groups
    # Each connection point group refers to a virtual link
    # the CP group consists of tuples of connection points
    cpgroup_list = []
    for i in range(external_vlr_count):
        cpgroup_list.append([])

    suffix = ''
    ping = VirtualNetworkFunction("ping_vnfd%s" % (suffix), pingcount)
    ping.use_vnf_init_conf = use_vnf_init_conf

    if use_placement_group:
        ### Add group name Eris
        group = VnfdPlacementGroup('Eris')
        group.add_strategy('COLOCATION')
        group.add_requirement('''Place this VM on the Kuiper belt object Eris''')
        ping.add_placement_group(group)

    # ping = VirtualNetworkFunction("ping_vnfd", pingcount)
    if not ping_userdata:
        ping_userdata = PING_USERDATA_FILE

    if ex_ping_userdata:
        ping_userdata = '''\
{ping_userdata}
{ex_ping_userdata}
        '''.format(
            ping_userdata=ping_userdata,
            ex_ping_userdata=ex_ping_userdata
        )

    ping.compose(
            "Fedora-x86_64-20-20131211.1-sda-ping.qcow2",
            ping_userdata,
            use_ping_cloud_init_file,
            "api/v1/ping/stats",
            get_ping_mon_params("api/v1/ping/stats") if use_mon_params else [],
            mon_port=18888,
            mgmt_port=18888,
            num_vlr_count=external_vlr_count,
            num_ivlr_count=internal_vlr_count,
            num_vms=num_vnf_vms,
            image_md5sum=ping_md5sum,
            mano_ut=mano_ut,
            )

    pong = VirtualNetworkFunction("pong_vnfd%s" % (suffix))

    if use_placement_group:
        ### Add group name Weywot
        group = VnfdPlacementGroup('Weywot')
        group.add_strategy('COLOCATION')
        group.add_requirement('''Place this VM on the Kuiper belt object Weywot''')
        pong.add_placement_group(group)


    # pong = VirtualNetworkFunction("pong_vnfd")

    if not pong_userdata:
        pong_userdata = PONG_USERDATA_FILE

    if ex_pong_userdata:
        pong_userdata = '''\
{pong_userdata}
{ex_pong_userdata}
        '''.format(
            pong_userdata=pong_userdata,
            ex_pong_userdata=ex_pong_userdata
        )


    pong.compose(
            "Fedora-x86_64-20-20131211.1-sda-pong.qcow2",
            pong_userdata,
            use_pong_cloud_init_file,
            "api/v1/pong/stats",
            get_pong_mon_params("api/v1/pong/stats") if use_mon_params else [],
            mon_port=18889,
            mgmt_port=18889,
            num_vlr_count=external_vlr_count,
            num_ivlr_count=internal_vlr_count,
            num_vms=num_vnf_vms,
            image_md5sum=pong_md5sum,
            mano_ut=mano_ut,
            )

    # Initialize the member VNF index
    member_vnf_index = 1

    # define the connection point groups
    for index, cp_group in enumerate(cpgroup_list):
        desc_id = ping.descriptor.vnfd[0].id
        filename = 'ping_vnfd{}/cp{}'.format(suffix, index)

        for idx in range(pingcount):
            cp_group.append((
                member_vnf_index,
                desc_id,
                filename,
                ))

            member_vnf_index += 1

        desc_id = pong.descriptor.vnfd[0].id
        filename = 'pong_vnfd{}/cp{}'.format(suffix, index)

        cp_group.append((
            member_vnf_index,
            desc_id,
            filename,
            ))

        member_vnf_index += 1

    vnfd_list = [ping, pong]

    nsd_catalog = NetworkService("ping_pong_nsd%s" % (suffix))

    if use_scale_group:
        group = ScaleGroup("ping_group", max_count=10)
        group.add_vnfd(ping, 1)
        group.add_config()
        nsd_catalog.add_scale_group(group)

    if use_placement_group:
        ### Add group name Orcus
        group = NsdPlacementGroup('Orcus')
        group.add_strategy('COLOCATION')
        group.add_requirement('''Place this VM on the Kuiper belt object Orcus''')

        for member_vnfd in vnfd_list:
            group.add_member(member_vnfd)

        nsd_catalog.add_placement_group(group)

        ### Add group name Quaoar
        group = NsdPlacementGroup('Quaoar')
        group.add_strategy('COLOCATION')
        group.add_requirement('''Place this VM on the Kuiper belt object Quaoar''')

        for member_vnfd in vnfd_list:
            group.add_member(member_vnfd)

        nsd_catalog.add_placement_group(group)


    nsd_catalog.compose(vnfd_list,
                        cpgroup_list,
                        mano_ut,
                        use_ns_init_conf=use_ns_init_conf,
                        use_vnf_init_conf=use_vnf_init_conf,)

    if write_to_file:
        ping.write_to_file(out_dir, ping_fmt if ping_fmt is not None else fmt)
        pong.write_to_file(out_dir, pong_fmt if ping_fmt is not None else fmt)
        nsd_catalog.write_config(out_dir, vnfd_list)
        nsd_catalog.write_to_file(out_dir, ping_fmt if nsd_fmt is not None else fmt)

    return (ping, pong, nsd_catalog)


def main(argv=sys.argv[1:]):
    global outdir, output_format, use_epa, aws, use_ping_cloud_init_file, use_pong_cloud_init_file
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--outdir', default='.')
    parser.add_argument('-f', '--format', default='json')
    parser.add_argument('-e', '--epa', action="store_true", default=False)
    parser.add_argument('-a', '--aws', action="store_true", default=False)
    parser.add_argument('-n', '--pingcount', default=NUM_PING_INSTANCES)
    parser.add_argument('--ping-image-md5')
    parser.add_argument('--pong-image-md5')
    parser.add_argument('--ping-cloud-init', default=None)
    parser.add_argument('--pong-cloud-init', default=None)
    args = parser.parse_args()
    outdir = args.outdir
    output_format = args.format
    use_epa = args.epa
    aws = args.aws
    pingcount = args.pingcount
    use_ping_cloud_init_file = args.ping_cloud_init
    use_pong_cloud_init_file = args.pong_cloud_init

    generate_ping_pong_descriptors(args.format, True, args.outdir, pingcount,
                                   ping_md5sum=args.ping_image_md5, pong_md5sum=args.pong_image_md5,
                                   mano_ut=False,
                                   use_scale_group=False,)

if __name__ == "__main__":
    main()
