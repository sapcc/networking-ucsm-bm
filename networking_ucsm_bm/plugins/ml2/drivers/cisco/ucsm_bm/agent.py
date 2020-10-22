# Copyright 2017 SAP SE
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import ssl
import sys
from bisect import insort
from collections import defaultdict
from contextlib import contextmanager

import attr
import oslo_messaging
import six
from neutron_lib.agent import topics
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service
from ucsmsdk.mometa.vnic.VnicEtherIf import VnicEtherIf
from ucsmsdk.ucshandle import UcsHandle

from networking_ucsm_bm import constants
from networking_ucsm_bm._i18n import _
from networking_ucsm_bm.plugins.ml2.drivers.cisco.ucsm_bm import exceptions as cexc
from networking_ucsm_bm.plugins.ml2.drivers.cisco.ucsm_bm.config import UcsmBmConfig
from neutron.common import config as common_config
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb  # noqa
from neutron.plugins.ml2.drivers.agent import _common_agent as ca  # noqa

try:
    from neutron.common import profiler
except ImportError:
    profiler = None

import eventlet
# oslo_messaging/notify/listener.py documents that monkeypatching is required
eventlet.monkey_patch()


###
# Basing it of CommonAgentManagerBase imposes some requirements,
# which may make the code look uncessecary complicated:
# - The manager needs to return a device in the known devices,
#   before ever receiving a port_binding request, other it will be filtered out,
#   as the base assumes, that it is not intended for this manager
#   => We know only MACs, so we return them
#      (CiscoUcsmBareMetalManager#get_all_devices)
# For getting the VLAN, we need to specify the device and the binding host.
# - The binding host is the uuid of the ironic bare-metal node, which we do not
#   know. But prior the binding, we receive a port_update, which allows us to
#   remember that association.
#   It does also gives us the UUID of the port, which we need to remember.
#   We do not receive the segment for our agent here though.
# - Ironic creates two ports with the same MAC, one in the management network,
#   the other one in the tenant network. Querying the device for the MAC
#   might give you either, so we have to query the port for its UUID
#   (which we have stored in CiscoUcsmBareMetalRpc#port_update)
# - Finally, as we query the device via the port UUID, the attribute 'device'
#   will be the UUID, the base expects it to be the MAC, as we return them in
#   CiscoUcsmBareMetalManager#get_all_devices.
#   => We have to change the 'device' field back to a MAC in
#      (AgentLoop#_get_devices_details_list)

ssl._create_default_https_context = ssl._create_unverified_context  # noqa
LOG = logging.getLogger(__name__)


class CiscoUcsmBareMetalRpc(amb.CommonAgentManagerRpcCallBackBase):
    target = oslo_messaging.Target(version='1.4')

    def security_groups_rule_updated(self, context, **kwargs):
        pass

    def security_groups_member_updated(self, context, **kwargs):
        pass

    def security_groups_provider_updated(self, context, **kwargs):
        pass

    def network_delete(self, context, **kwargs):
        pass

    def port_update(self, context, **kwargs):
        port = kwargs['port']
        LOG.debug("port_update received for port %s ", port)
        self.agent.mgr.set_mapping(port)
        self.updated_devices.add(port['mac_address'])


@attr.s
class _PortInfo(object):
    port_id = attr.ib(default=None)
    ucsm_ip = attr.ib(default=None)
    binding_host_id = attr.ib(default=None)


def for_all_hosts(f):
    six.wraps(f)

    def wrapper(self, *args, **kwds):
        for ucsm_ip in self.ucsm_conf.get_all_ucsm_ips():
            with self.ucsm_connect_disconnect(ucsm_ip) as handle:
                kwds['handle'] = handle
                yield ucsm_ip, f(self, *args, **kwds)

    return wrapper


class CiscoUcsmBareMetalManager(amb.CommonAgentManagerBase):
    def get_agent_api(self, **kwargs):
        pass

    def __init__(self, config):
        super(amb.CommonAgentManagerBase, self).__init__()
        self.ucsm_conf = config
        self._ports = defaultdict(_PortInfo)
        self._mac_blocks = self._discover_mac_blocks()
        self._discover_devices()

    @for_all_hosts
    def get_all(self, class_id, path=None, handle=None):
        for device in handle.query_classid(class_id=class_id):
            yield device

    def _discover_mac_blocks(self, path=None):
        blocks = []
        for first, last, ucsm_ip in self.get_all_mac_blocks(path):
            insort(blocks, (first, last, ucsm_ip))
        return blocks

    def get_all_mac_blocks(self, path=None):
        macpool_block_id = "MacpoolBlock"
        for ucsm_ip, blocks in self.get_all(macpool_block_id):
            for block in blocks:
                yield block.r_from.lower(), block.to.lower(), ucsm_ip

    def get_rpc_callbacks(self, context, agent, sg_agent):
        return CiscoUcsmBareMetalRpc(context, agent, sg_agent)

    def ensure_port_admin_state(self, device, admin_state_up):
        pass

    def set_mapping(self, port):
        port_id = port['id']
        mac = port['mac_address']
        binding_host_id = port['binding:host_id']

        LOG.debug("Bound {} to {}".format(mac, binding_host_id))
        info = self._ports[mac.lower()]
        info.port_id = port_id
        info.binding_host_id = binding_host_id

    def get_agent_configurations(self):
        # The very least, we have to return the physical networks as keys
        # of the bridge_mappings
        return {
            'physical_networks': self.ucsm_conf.get_networks(), 'mac_blocks': [
                (block[0], block[1]) for block in self._mac_blocks]}

    def get_agent_id(self):
        return 'cisco-ucs-bm-agent-%s' % cfg.CONF.host

    def get_all_devices(self):
        return set(six.iterkeys(self._ports))

    def get_devices_modified_timestamps(self, devices):
        return {}

    def get_extension_driver_type(self):
        return 'ucsm_bm'

    def get_port_info(self, device):
        if device in self._ports:
            return self._ports[device.lower()]

    def get_rpc_consumers(self):
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE]]
        return consumers

    def plug_interface(self, network_id, network_segment,
                       device, device_owner):
        LOG.debug("Start {}".format(device))
        vlan_id = network_segment.segmentation_id

        info = self._ports.get(device.lower())
        if not info or not info.ucsm_ip:
            LOG.debug("Unknown device {}".format(device))
            return False

        with self.ucsm_connect_disconnect(info.ucsm_ip) as handle:
            vlans = self._get_vlan(handle, vlan_id)
            if len(vlans) != 1:
                LOG.error(
                    "Cannot uniquely identify vlan {} for {}".format(
                        vlan_id, device))
                return False
            vlan = vlans[0]

            filter = '(addr, "{}", type="eq")'.format(device)
            for eth in handle.query_classid('VnicEther', filter_str=filter):
                exists = False
                to_delete = []
                for eth_if in handle.query_children(eth, class_id='vnicEtherIf'):
                    if eth_if.name != vlan.name:
                        to_delete.append(eth_if)
                    else:
                        exists = True

                if to_delete:
                    LOG.debug("Removing {}".format(
                        [eth_if.dn for eth_if in to_delete]))
                    for mo in to_delete:
                        handle.remove_mo(mo)
                        pass

                if exists:
                    LOG.debug("Already bound {}".format(vlan.name))
                else:
                    LOG.debug("Adding {}".format(vlan.name))
                    mo = VnicEtherIf(eth, default_net="yes", name=vlan.name)
                    handle.add_mo(mo, modify_present=True)
            handle.commit()

        LOG.debug("Done")
        return True

    def _get_vlan(self, handle, vlan_id):
        filter = '(id, "{}", type="eq")'.format(vlan_id)
        filter += ' and (transport, "ether", type="eq")'
        filter += ' and (if_type, "virtual", type="eq")'
        return handle.query_classid(class_id='FabricVlan',
                                    filter_str=filter)

    def setup_arp_spoofing_protection(self, device, device_details):
        pass

    def delete_arp_spoofing_protection(self, devices):
        pass

    def delete_unreferenced_arp_protection(self, current_devices):
        pass

    @contextmanager
    def ucsm_connect_disconnect(self, ucsm_ip):
        handle = self.ucs_manager_connect(ucsm_ip)
        try:
            yield handle
        finally:
            self.ucs_manager_disconnect(handle, ucsm_ip)

    def ucs_manager_connect(self, ucsm_ip):
        """Connects to a UCS Manager."""
        username, password = self.ucsm_conf.get_credentials_for_ucsm_ip(
            ucsm_ip)
        if not username:
            LOG.error(_('UCS Manager network driver failed to get login '
                        'credentials for UCSM %s'), ucsm_ip)
            return None

        try:
            handle = UcsHandle(ucsm_ip, username, password)
            handle.login()
        except Exception as e:
            # Raise a Neutron exception. Include a description of
            # the original  exception.
            raise cexc.UcsmConnectFailed(ucsm_ip=ucsm_ip, exc=e)

        return handle

    def ucs_manager_disconnect(self, handle, ucsm_ip):
        """Disconnects from the UCS Manager.

        After the disconnect, the handle associated with this connection
        is no longer valid.
        """
        try:
            handle.logout()
        except Exception as e:
            # Raise a Neutron exception. Include a description of
            # the original  exception.
            raise cexc.UcsmDisconnectFailed(ucsm_ip=ucsm_ip, exc=e)

    def _discover_devices(self):
        class_id = "VnicEther"
        for ucsm_ip in self.ucsm_conf.get_all_ucsm_ips():
            vnic_paths = self.ucsm_conf.vnic_paths_dict[ucsm_ip]
            with self.ucsm_connect_disconnect(ucsm_ip) as handle:
                for vnic_path in vnic_paths:
                    filter = '(dn,"{}.*", type="re")'.format(vnic_path)
                    for vnicEther in handle.query_classid(class_id=class_id, filter_str=filter):
                        self._ports[vnicEther.addr.lower()].ucsm_ip = ucsm_ip


class AgentLoop(ca.CommonAgentLoop):
    def _get_devices_details_list(self, devices):
        devices_by_host = defaultdict(list)
        for device in devices:
            port_info = self.mgr.get_port_info(device)
            if port_info and port_info.binding_host_id and port_info.port_id:
                devices_by_host[port_info.binding_host_id].append(
                    port_info.port_id)
        device_details = []
        for host, devices_on_host in six.iteritems(devices_by_host):
            LOG.debug("Querying {} for {}".format(devices_on_host, host))
            for device in self.plugin_rpc.get_devices_details_list(
                    self.context, devices_on_host, self.agent_id, host=host):
                mac_address = device.get('mac_address')
                if mac_address:
                    device['device'] = mac_address
                device_details.append(device)

        LOG.debug("Found {}".format(device_details))
        return device_details


def main():
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    if profiler:
        profiler.setup(constants.AGENT_BINARY, cfg.CONF.host)
    config = UcsmBmConfig()
    manager = CiscoUcsmBareMetalManager(config)

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = AgentLoop(manager, polling_interval,
                      quitting_rpc_timeout,
                      constants.AGENT_TYPE,
                      constants.AGENT_BINARY)
    LOG.info(_("Agent initialized successfully, now running... "))
    launcher = service.launch(cfg.CONF, agent)
    launcher.wait()
