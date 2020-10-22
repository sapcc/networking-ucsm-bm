# Copyright 2017-2019 SAP SE
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

from bisect import bisect

from neutron_lib import constants as p_const
from neutron_lib.agent import topics
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging

import networking_ucsm_bm.constants as constants
from networking_ucsm_bm._i18n import _
from neutron.db import provisioning_blocks
from neutron.plugins.ml2 import rpc as ml2_rpc
from neutron.plugins.ml2.drivers.mech_agent import SimpleAgentMechanismDriverBase

LOG = logging.getLogger(__name__)


class CiscoUcsmBareMetalDriver(SimpleAgentMechanismDriverBase):
    def __init__(self):
        vif_details = {portbindings.CAP_PORT_FILTER: False,
                       portbindings.OVS_HYBRID_PLUG: False}
        self.notifier = ml2_rpc.AgentNotifierApi(topics.AGENT)

        super(
            CiscoUcsmBareMetalDriver,
            self).__init__(
            constants.AGENT_TYPE,
            portbindings.VIF_TYPE_OTHER,
            vif_details,
            supported_vnic_types=[
                portbindings.VNIC_BAREMETAL])

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        agents = self._get_agents(context)
        if not agents:
            LOG.warning(_("Port %(pid)s on network %(network)s not bound, "
                          "no agent registered of tpy %(agent_type)s"),
                        {'pid': context.current['id'],
                         'network': context.network.current['id'],
                         'agent_type': self.agent_type})
        for agent in agents:
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if self.try_to_bind_segment_for_agent(context, segment,
                                                          agent):
                        LOG.debug("Bound using segment: %s", segment)
                        self._notify_port_updated(context)
                        return
            else:
                LOG.warning(_("Refusing to bind port %(pid)s to dead agent: "
                              "%(agent)s"),
                            {'pid': context.current['id'], 'agent': agent})

    def _notify_port_updated(self, mech_context):
        port = mech_context.current
        segment = mech_context.bottom_bound_segment
        if not segment:
            # REVISIT(rkukura): This should notify agent to unplug port
            network = mech_context.network.current
            LOG.debug("In _notify_port_updated(), no bound segment for "
                      "port %(port_id)s on network %(network_id)s",
                      {'port_id': port['id'], 'network_id': network['id']})
            return
        self.notifier.port_update(mech_context._plugin_context, port,
                                  segment[api.NETWORK_TYPE],
                                  segment[api.SEGMENTATION_ID],
                                  segment[api.PHYSICAL_NETWORK])

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        mac_address = context.current['mac_address'].lower()
        mac_blocks = agent['configurations'].get('mac_blocks', [])

        # bisect will yield the pos (i) behind the last value, which is <=.
        # i-1 would then be the block containing the mac address
        # 'z' is always larger than a mac address, so if the mac_address
        # coincides with the beginning of a block, it will still yield a position
        # after the block, as it will if the mac_address is behind the
        # beginning of the block
        pos = bisect(mac_blocks, [mac_address, 'z']) - 1

        if pos < 0:
            LOG.debug("Mac address out of range for agent")
            return False

        if mac_address < mac_blocks[pos][0] or mac_blocks[pos][1] < mac_address:
            LOG.debug("Mac address out of range for agent")
            return False

        return SimpleAgentMechanismDriverBase.try_to_bind_segment_for_agent(
            self, context, segment, agent)

    def _insert_provisioning_block(self, context):
        # we insert a status barrier to prevent the port from transitioning
        # to active until the agent reports back that the wiring is done
        port = context.current
        if not context.host or port['status'] == p_const.PORT_STATUS_ACTIVE:
            # no point in putting in a block if the status is already ACTIVE
            return
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            # we check the VNIC type because there could be multiple agents
            # on a single host with different VNIC types
            return
        if self._get_agents(context):
            provisioning_blocks.add_provisioning_component(
                context._plugin_context, port['id'], resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)

    def get_allowed_network_types(self, _=None):
        return p_const.TYPE_FLAT, p_const.TYPE_VLAN

    def get_mappings(self, agent):
        items = []
        for item in agent['configurations'].get('physical_networks', []):
            if isinstance(item, list):
                items.extend(item)
            else:
                items.append(item)

        return items

    @staticmethod
    def _get_agents(context):
        filters = {'agent_type': constants.AGENT_TYPE}
        return context._plugin.get_agents(context._plugin_context,
                                            filters)
