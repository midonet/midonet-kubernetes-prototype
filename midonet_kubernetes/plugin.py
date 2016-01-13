#!/usr/bin/env python

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import print_function

import logging
import os
import subprocess
import sys
import traceback

import docker
from neutronclient.common import exceptions as n_exceptions
from neutronclient.v2_0 import client as client_v2
import netaddr
from oslo_concurrency import processutils
from pybrctl import pybrctl
import pyroute2

# from midonet_kubernetes import actions
import actions
import exceptions


LOG_PATH = '/var/log/midonet-kubernetes/plugin.log'

logging.basicConfig(filename=LOG_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)

BINDING_EXECUTABLE='/usr/bin/mm-ctl'
BIND='--bind-port'
UNBIND='--unbind-port'
HOST = os.environ.get('OS_HOST', '')
ENDPOINT_URL = 'http://{0}:9696'.format(HOST)
USERNAME = 'admin'
TENANT_NAME = 'admin'
PASSWORD = 'midonet'
AUTH_URL = 'http://{0}:35357/v2.0'.format(HOST)
NETNS_PREFIX = '/var/run/netns/'
PROC_TEMPLATE = '/proc/{0}/ns/net'
GLOBAL_ROUTER_NAME = 'midonet-kubernetes'


neutron = client_v2.Client(endpoint_url=ENDPOINT_URL, timeout=30,
                           username=USERNAME, tenant_name=TENANT_NAME,
                           password=PASSWORD, auth_url=AUTH_URL)
neutron.format = 'json'

docker_client = docker.Client(base_url='unix:///var/run/docker.sock')

docker_bridge = pybrctl.Bridge("docker0")


def _get_short_docker_id(docker_id):
    return docker_id[:12]


def _get_networks_by_attrs(unique=True, **attrs):
    networks = neutron.list_networks(**attrs)
    if unique and len(networks.get('networks', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron networks exist for the params {0}"
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return networks['networks']


def _get_subnets_by_attrs(unique=True, **attrs):
    subnets = neutron.list_subnets(**attrs)
    if unique and len(subnets.get('subnets', [])) > 2:  # subnets for IPv4 and/or IPv6
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron subnets exist for the params {0} "
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return subnets['subnets']


def _get_ports_by_attrs(unique=True, **attrs):
    ports = neutron.list_ports(**attrs)
    if unique and len(ports.get('ports', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron ports exist for the params {0} "
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return ports['ports']


def _get_routers_by_attrs(unique=True, **attrs):
    routers = neutron.list_routers(**attrs)
    if unique and len(routers.get('routers', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron routers exist for the params {0}"
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return routers['routers']


def init():
    """Initializes the network plugin.

    This function is called when 'init' is given as the first argument.
    """
    logger.info('Initialized the plugin')


def get_veth_name_for_container(container_info):
    """Returns the name of the veth interface associated with the container

    :param container_id: the container info dictionary returned by Docker API
    :returns: the veth name as string
    """
    logger.info(container_info)
    container_id = container_info['Id']
    sandbox_id = container_info['NetworkSettings']['SandboxID'][:12]
    if not os.path.exists(NETNS_PREFIX):
        os.mkdir(NETNS_PREFIX)
    pid = container_info['State']['Pid']
    proc_dir = PROC_TEMPLATE.format(pid)
    netns_symlink_path = NETNS_PREFIX + str(pid)
    veth_name = ''

    try:
        if not os.path.exists(netns_symlink_path):
            os.symlink(proc_dir, netns_symlink_path)
            logger.debug('Created a symlink {0}'.format(netns_symlink_path))
        container_netns = pyroute2.IPDB(nl=pyroute2.NetNS(str(pid)))
        
        main_netns = pyroute2.IPDB()
        try:
            logger.debug(container_netns.interfaces)
            # logger.debug(main_netns.interfaces)
            with container_netns.by_name['eth0'] as eth0:
                eth0_index = eth0['index']
                veth_index = eth0_index + 1
                with main_netns.by_index[veth_index] as veth:
                    veth_name = veth['ifname']
        finally:
            container_netns.release()
            main_netns.release()
    finally:
        if os.path.exists(netns_symlink_path):
            os.remove(netns_symlink_path)
            logger.debug('Deleted the symlink {0}'.format(netns_symlink_path))

    return veth_name


def _get_or_create_subnet(container_info, neutron_network_id=''):
    ip_address = container_info['NetworkSettings']['IPAddress']
    prefixlen = container_info['NetworkSettings']['IPPrefixLen']
    gateway_ip = container_info['NetworkSettings']['Gateway']
    cidr = netaddr.IPNetwork('/'.join([ip_address, str(prefixlen)]))
    subnet_network = str(cidr.network)
    subnet_cidr = '/'.join([subnet_network, str(cidr.prefixlen)])
    created_subnet = {}
    subnets = _get_subnets_by_attrs(cidr=str(subnet_cidr))
    if not subnets:
        new_subnet = {
            'network_id': neutron_network_id,
            'ip_version': cidr.version,
            'cidr': subnet_cidr,
            'gateway_ip': gateway_ip,
            'enable_dhcp': False,
        }
        created_subnet_response = neutron.create_subnet({'subnet': new_subnet})
        created_subnet = created_subnet_response['subnet']
    else:
        created_subnet = subnets[0]
        logger.debug('Reusing the existing subnet {0}'
                     .format(created_subnet['id']))

    return created_subnet


def _get_or_create_router(pod_namespace):
    router_name = pod_namespace
    routers = _get_routers_by_attrs(name=router_name)
    router = {}
    if not routers:
	created_router_resopnse = neutron.create_router(
	    {'router': {'name': router_name}})
	router = created_router_resopnse['router']
	logger.debug('Created the router {0}'.format(router))
    else:
	router = routers[0]
	logger.debug('Reusing the router {0}'.format(router['id']))

    return router


def _create_port(container_info, neutron_network_id,
                 neutron_subnet_id, pod_name):
    ip_address = container_info['NetworkSettings']['IPAddress']
    mac_address = container_info['NetworkSettings']['MacAddress']
    new_port = {
        'name': pod_name,
        'network_id': neutron_network_id,
        'mac_address': mac_address,
        'fixed_ips': [{
            'subnet_id': neutron_subnet_id,
            'ip_address': ip_address,
        }],
    }
    created_port_response = neutron.create_port({'port': new_port})
    created_port = created_port_response['port']

    return created_port


def setup(pod_namespace, pod_name, container_id):
    """Creates the network for the container.

    This function is called when 'setup' is given as the first argument.
    """
    network = []
    # Map Pod's namespace into Neutron network.
    networks = _get_networks_by_attrs(name=pod_namespace)
    if not networks:
        created_network_response = neutron.create_network(
            {'network': {'name': pod_namespace}})
        network = created_network_response['network']
        logger.debug('Created the network {0}'.format(network))
    else:
        network = networks[0]
        logger.debug('Reusing the network {0}'.format(network['id']))

    container_info = docker_client.inspect_container(container_id)

    # Create a new subnet if the corresponding one doesn't exist.
    subnet = _get_or_create_subnet(container_info, network['id'])

    router = _get_or_create_router(GLOBAL_ROUTER_NAME)

    neutron_router_id = router['id']
    neutron_subnet_id = subnet['id']
    filtered_ports = _get_ports_by_attrs(
	unique=False,  device_owner='network:router_interface',
	device_id=neutron_router_id)

    router_ports = [port for port in filtered_ports
		    if ((neutron_subnet_id in [
			fip['subnet_id'] for fip in port.get('fixed_ips', [])])
			or (neutron_subnet_id == port.get('subnet_id', '')))]

    if not router_ports:
	neutron.add_interface_router(
	    neutron_router_id, {'subnet_id': neutron_subnet_id})
    else:
	logger.debug('The subnet {0} is already bound to the router'
		     .format(neutron_subnet_id))

    port = _create_port(container_info, network['id'], subnet['id'], pod_name)

    # Getting the veth name.
    veth_name = get_veth_name_for_container(container_info)

    docker_bridge.delif(veth_name)
    port_id = port['id']
    try:
        stdout, stderr = processutils.execute(
            BINDING_EXECUTABLE, BIND, port_id, veth_name,
            run_as_root=True)
    except processutils.ProcessExecutionError as ex:
        logger.error('Binding the port is failed: {0}'.format(ex))
        sys.exit(-1)

    logger.debug('Successfully bound the port {0} to {1}'
                 .format(port_id, veth_name))


def teardown(pod_namespace, pod_name, container_id):
    """Destroys the network for the container.

    This function is called when 'teardown' is given as the first argument.
    """
    container_info = docker_client.inspect_container(container_id)

    filtered_ports = _get_ports_by_attrs(name=pod_name)
    if filtered_ports:
        port_id = filtered_ports[0]['id']
        try:
            stdout, stderr = processutils.execute(
                BINDING_EXECUTABLE, UNBIND, port_id, run_as_root=True)
        except processutils.ProcessExecutionError as ex:
            logger.error('Unbinding the port is failed: {0}'.format(ex))
            sys.exit(-1)
        logger.debug('Successfully unbound the port {0}'.format(port_id))

        neutron.delete_port(port_id)
        logger.debug('Successfuly deleted the port {0}'.format(port_id))

    subnet = _get_or_create_subnet(container_info)
    neutron_subnet_id = subnet['id']

    router = _get_or_create_router(GLOBAL_ROUTER_NAME)
    neutron_router_id = router['id']

    try:
        neutron.delete_subnet(neutron_subnet_id)
	logger.debug('Deleted the subnet {0}'.format(neutron_subnet_id))
    except n_exceptions.Conflict as ex:
        logger.info('The subnet {0} is still in use.'
                    .format(neutron_subnet_id))

    try:
	neutron.delete_router(neutron_router_id)
 	logger.debug('Deleted the router {0}'.format(neutron_subnet_id))
    except n_exceptions.Conflict as ex:
	logger.info('The router {0} is still in use.'
		    .format(neutron_router_id))

    filtered_networks = _get_networks_by_attrs(name=pod_namespace)
    neutron_network_id = filtered_networks[0]['id']
    try:
        neutron.delete_network(neutron_network_id)
    except n_exceptions.Conflict as ex:
        logger.info('The network {0} is still in use.'
                    .format(neutron_network_id))

    logger.debug('Deleleted the network {0}'.format(neutron_network_id))


def status(pod_namespace, pod_name, container_id):
    """Reports the status of the containers identifed by the given information.

    This function is called when 'status' is given as the first argument.
    """
    pass


def dispatch(action, pod_namespace=None, pod_name=None, container_id=None):
    """Run the actual action with the given arguments.

    Curretly the following actions are supported.

    - init
    - setup <pod_namespace> <pod_name> <container_id>
    - teardown <pod_namespace> <pod_name> <container_id>
    - status <pod_namespace> <pod_name> <container_id>

    After executing the action, it exits with the return code 0. Otherwise it
    eixits with the non-zero return code.

    See the following link for more details.

    - https://godoc.org/github.com/kubernetes/kubernetes/pkg/kubelet/network/exec  # noqa
    """

    if action == actions.INIT:
        logger.debug('init is called.')
        init()
    elif action == actions.SETUP:
        logger.debug('setup is called.')
        setup(pod_namespace, pod_name, container_id)
    elif action == actions.TEARDOWN:
        logger.debug('teardown is called.')
        teardown(pod_namespace, pod_name, container_id)
    elif action == actions.STATUS:
        logger.debug('status is called.')
        status(pod_namespace, pod_name, container_id)

    sys.exit(0)


def _dispatch_log():
    """Dispatches the action and catch exceptions to be logged.

    After executing the action, it exits with return code 0 if it succeeded to
    run through. Othereise it exits with the non-zero return code.
    """
    args = sys.argv
    action = args[1]
    pod_namespace = args[2] if len(args) > 3 else None
    pod_name = args[3] if len(args) > 4 else None
    container_id = args[4] if len(args) >= 5 else None

    logger.debug("MidoNet plugin executable was called with action: {0}, "
                 "pod_namespace: {1}, pod_name: {2}, container_id: {3}"
                 .format(action, pod_namespace, pod_name, container_id))

    return_code = 0
    try:
        dispatch(action, pod_namespace=pod_namespace,
                 pod_name=pod_name,
                 container_id=container_id)
    except SystemExit, e:
        return_code = e.code
    except Exception, e:
        logger.error("Unhandled exception: %s", e)
        logger.error(traceback.format_exc())
        return_code = -1
    finally:
        logger.debug("MidoNet plugin succeeded to be executed: %s",
                     return_code)
        sys.exit(return_code)


if __name__ == '__main__':
    _dispatch_log()
