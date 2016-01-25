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

import json
import logging
import os
import requests
import socket
import sys
import traceback

import docker
from neutronclient.common import exceptions as n_exceptions
from neutronclient.v2_0 import client as client_v2
import netaddr
from oslo_concurrency import lockutils
from oslo_concurrency import processutils
from pybrctl import pybrctl
import pyroute2

# from midonet_kubernetes import actions
import actions
import exceptions


LOG_PATH = '/var/log/midonet-kubernetes/plugin.log'

logging.basicConfig(filename=LOG_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)

BINDING_EXECUTABLE = '/usr/bin/mm-ctl'
BIND = '--bind-port'
UNBIND = '--unbind-port'
HOST = os.environ.get('OS_HOST', '')
ENDPOINT_URL = 'http://{0}:9696'.format(HOST)
USERNAME = 'admin'
TENANT_NAME = 'admin'
PASSWORD = 'midonet'
AUTH_URL = 'http://{0}:35357/v2.0'.format(HOST)
NETNS_PREFIX = '/var/run/netns/'
PROC_TEMPLATE = '/proc/{0}/ns/net'
GLOBAL_ROUTER_NAME = 'midonet-kubernetes'
# GLOBAL_ROUTER_NAME = 'my_router'
SUBNET_RANGE = os.environ.get('SERVICE_CLUSTER_IP_RANGE', '192.168.3.0/24')

KUBE_API_SERVER_HOST = '10.240.0.12'
KUBE_API_SERVER_PORT = '8080'
KUBE_API_SERVER_URL = 'http://{0}:{1}/api/v1'.format(
    KUBE_API_SERVER_HOST, KUBE_API_SERVER_PORT)

neutron = client_v2.Client(endpoint_url=ENDPOINT_URL, timeout=30,
                           username=USERNAME, tenant_name=TENANT_NAME,
                           password=PASSWORD, auth_url=AUTH_URL)
neutron.format = 'json'

docker_client = docker.Client(base_url='unix:///var/run/docker.sock')

docker_bridge = pybrctl.Bridge("docker0")


def get_hostname():
    """Returns the host name."""
    return socket.gethostname()


def _get_short_docker_id(docker_id):
    return docker_id[:12]


def _get_network_name(pod_namespace, host_name):
    # return '-'.join([pod_namespace, host_name])
    return pod_namespace


def _call_k8s_api(endpoint='/'):
    response = requests.get(KUBE_API_SERVER_URL + endpoint)
    return response.json()


def get_services(pod_namespace):
    return _call_k8s_api('/namespaces/{0}/services'.format(pod_namespace))


def get_service(pod_namespace, service_name):
    return _call_k8s_api('/namespaces/{0}/services/{1}'
                         .format(pod_namespace, service_name))


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


def _get_vips_by_attrs(unique=True, **attrs):
    vips = neutron.list_vips(**attrs)
    if unique and len(vips.get('vips', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron vips exist for the params {0} "
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return vips['vips']


def _get_pools_by_attrs(unique=True, **attrs):
    pools = neutron.list_pools(**attrs)
    if unique and len(pools.get('pools', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron pools exist for the params {0} "
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return pools['pools']


def _get_members_by_attrs(unique=True, **attrs):
    members = neutron.list_members(**attrs)
    if unique and len(members.get('members', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron members exist for the params {0} "
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return members['members']


def _get_router_ports_by_subnet_id(neutron_subnet_id, neutron_port_list):
    router_ports = [
        port for port in neutron_port_list
        if ((neutron_subnet_id in [fip['subnet_id']
                                   for fip in port.get('fixed_ips', [])])
            or (neutron_subnet_id == port.get('subnet_id', '')))]

    return router_ports


def init():
    """Initializes the network plugin.

    This function is called when 'init' is given as the first argument.
    """
    logger.info('Initialized the plugin')


def get_veth_name_for_container(container_info):
    """Returns the name of the veth interface associated with the container

    :param container_info: the container info dictionary returned by Docker API
    :returns: the veth name as string
    """
    logger.info(container_info)
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
    subnets = _get_subnets_by_attrs(cidr=str(subnet_cidr),
                                    network_id=neutron_network_id)
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


def _get_or_create_cluster_ip_subnet(neutron_network_id=''):
    ip_network = netaddr.IPNetwork(SUBNET_RANGE)
    subnets = _get_subnets_by_attrs(cidr=SUBNET_RANGE,
                                    network_id=neutron_network_id)
    if not subnets:
        new_subnet = {
            'network_id': neutron_network_id,
            'ip_version': ip_network.version,
            'cidr': SUBNET_RANGE,
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


def _get_or_create_pools_and_vips(service_name, subnet_id, service_spec):
        cluster_ip = service_spec['clusterIP']
        ports = service_spec['ports']
        pools = []
        vips = []
        for port in ports:
            protocol = port['protocol']
            protocol_port = port['targetPort']
            neutron_pools = _get_pools_by_attrs(
                name=service_name, protocol=protocol, subnet_id=subnet_id)
            neutron_pool = {}
            if not neutron_pools:
                pool_request = {
                    'pool': {
                        'name': service_name,
                        'protocol': protocol,
                        'subnet_id': subnet_id,
                        'lb_method': 'ROUND_ROBIN',
                    },
                }
                neutron_pool_response = neutron.create_pool(pool_request)
                neutron_pool = neutron_pool_response['pool']
            else:
                neutron_pool = neutron_pools[0]
            pools.append(neutron_pool)

            pool_id = neutron_pool['id']
            neutron_vips = _get_vips_by_attrs(
                name=service_name, protocol=protocol, subnet_id=subnet_id,
                pool_id=pool_id, ddress=cluster_ip)
            neutron_vip = {}
            if not neutron_vips:
                vip_request = {
                    'vip': {
                        # name is not necessary unique and the service name is
                        # used for the group of the vips.
                        'name': service_name,
                        'pool_id': pool_id,
                        'subnet_id': subnet_id,
                        'address': cluster_ip,
                        'protocol': protocol,
                        'protocol_port': protocol_port,
                    },
                }
                neutron_vip_response = neutron.create_vip(vip_request)
                neutron_vip = neutron_vip_response['vip']
            else:
                neutron_vip = neutron_vips[0]
            vips.append(neutron_vip)

        return (pools, vips)


def _get_ip_address_in_port(neutron_port):
    ip_address = neutron_port.get('ip_address', '')
    fixed_ips = neutron_port.get('fixed_ips', [])
    if not ip_address:
        for fixed_ip in fixed_ips:
            ip = netaddr.IPAddress(fixed_ip['ip_address'])
            if ip.version == 4:
                ip_address = fixed_ip['ip_address']
                break

        return ip_address


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


def get_service_name(pod_name):
    """Returns the service name from the pod name."""
    return pod_name[:-6]


def _emulate_kube_proxy(pod_namespace, pod_name, cluster_ip_subnet_id, neutron_port):
    service_name = get_service_name(pod_name)
    service = get_service(pod_namespace, service_name)
    service_spec = service['spec']

    pools, vips = _get_or_create_pools_and_vips(
        service_name, cluster_ip_subnet_id, service_spec)
    # NOTE(tfukushima): The current Neutron model assumes the single VIP can be
    # create under the same subnet, which is not true in K8s assumption. This
    # introduces the limitation that we support only the single "port" entity
    # in the "ports" secton of the spec file.
    neutron_pool = pools[0]
    neutron_vip = vips[0]
    member_request = {
        'member': {
            'pool_id': neutron_pool['id'],
            'address': _get_ip_address_in_port(neutron_port),
            'protocol_port': neutron_vip['protocol_port'],
            'weight': 1,
        }
    }
    neutron_member_response = neutron.create_member(member_request)
    neutron_member = neutron_member_response['member']

    logger.debug('Created a new member {0} for the pool {1} associated with the'
                 'vip {2}'
                 .format(neutron_member['id'], neutron_pool['id'],
                         neutron_vip['id']))


def _cleanup_emulated_kube_proxy(pod_namespace, pod_name, cluster_ip_subnet_id, port):
    service_name = get_service_name(pod_name)
    services = get_services(pod_namespace)
    logger.debug('services: {0}'.format(services))

    service = get_service(pod_namespace, service_name)
    logger.debug('service: {0}'.format(service))
    service_spec = service['spec']

    pools, vips = _get_or_create_pools_and_vips(
        service_name, cluster_ip_subnet_id, service_spec)
    neutron_pool = pools[0]
    neutron_vip = vips[0]

    address = _get_ip_address_in_port(port)
    pool_id = neutron_pool['id']
    member = _get_members_by_attrs(address=address, pool_id=pool_id)
    neutron.delete_member(member['id'])

    vip_id = neutron_vip['id']
    try:
        neutron.delete_vip(vip_id)
    except n_exceptions.Conflict:
        logger.info('The vip {0} is still in use.'.format(vip_id))

    try:
        neutron.delete_pool(pool_id)
    except n_exceptions.Conflict:
        logger.info('the pool {0} is still in use.'.format(pool_id))

    logger.debug('Successfully cleaned the emulated kube-proxy resources up')


@lockutils.synchronized('k8s-np-lock', lock_file_prefix='k8s-np-lock',
                        external=True, lock_path='/tmp/')
def setup(pod_namespace, pod_name, container_id):
    """Creates the network for the container.

    This function is called when 'setup' is given as the first argument.
    """
    network = {}
    # Map Pod's namespace into Neutron network.
    network_name = _get_network_name(pod_namespace, get_hostname())
    networks = _get_networks_by_attrs(name=network_name)
    if not networks:
        created_network_response = neutron.create_network(
            {'network': {'name': network_name}})
        network = created_network_response['network']
        logger.debug('Created the network {0}'.format(network))
    else:
        network = networks[0]
        logger.debug('Reusing the network {0}'.format(network['id']))
    neutron_network_id = network['id']

    container_info = docker_client.inspect_container(container_id)

    # Create a new subnet if the corresponding one doesn't exist.
    subnet = _get_or_create_subnet(container_info, network['id'])

    router = _get_or_create_router(GLOBAL_ROUTER_NAME)

    neutron_router_id = router['id']
    neutron_subnet_id = subnet['id']
    filtered_ports = _get_ports_by_attrs(
        unique=False, device_owner='network:router_interface',
        device_id=neutron_router_id, network_id=neutron_network_id)

    router_ports = _get_router_ports_by_subnet_id(
        neutron_subnet_id, filtered_ports)

    if not router_ports:
        neutron.add_interface_router(
            neutron_router_id, {'subnet_id': neutron_subnet_id})
    else:
        logger.debug('The subnet {0} is already bound to the router'
                     .format(neutron_subnet_id))

    cluster_ip_subnet = _get_or_create_cluster_ip_subnet(network['id'])
    cluster_ip_subnet_id = cluster_ip_subnet['id']
    cluster_ip_router_ports = _get_router_ports_by_subnet_id(
        cluster_ip_subnet_id, filtered_ports)

    if not cluster_ip_router_ports:
        neutron.add_interface_router(
            neutron_router_id, {'subnet_id': cluster_ip_subnet_id})
    else:
        logger.debug('The cluster IP subnet {0} is already bound to the router'
                     .format(cluster_ip_subnet_id))

    port = _create_port(container_info, neutron_network_id,
                        neutron_subnet_id, pod_name)
    logger.debug('Created a new port {0}'.format(port['id']))

    _emulate_kube_proxy(pod_namespace, pod_name, cluster_ip_subnet_id, port)

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


@lockutils.synchronized('k8s-np-lock', lock_file_prefix='k8s-np-lock',
                        external=True, lock_path='/tmp/')
def teardown(pod_namespace, pod_name, container_id):
    """Destroys the network for the container.

    This function is called when 'teardown' is given as the first argument.
    """
    network_name = _get_network_name(pod_namespace, get_hostname())
    filtered_networks = _get_networks_by_attrs(name=network_name)
    neutron_network_id = filtered_networks[0]['id']

    container_info = docker_client.inspect_container(container_id)

    filtered_ports = _get_ports_by_attrs(name=pod_name)
    if filtered_ports:
        port = filtered_ports[0]
        port_id = port['id']
        try:
            stdout, stderr = processutils.execute(
                BINDING_EXECUTABLE, UNBIND, port_id, run_as_root=True)
        except processutils.ProcessExecutionError as ex:
            logger.error('Unbinding the port is failed: {0}'.format(ex))
            sys.exit(-1)
        logger.debug('Successfully unbound the port {0}'.format(port_id))

        cluster_ip_subnet = _get_or_create_cluster_ip_subnet(neutron_network_id)
        cluster_ip_subnet_id = cluster_ip_subnet['id']

        _cleanup_emulated_kube_proxy(pod_namespace, pod_name, cluster_ip_subnet_id, port)

        neutron.delete_port(port_id)
        logger.debug('Successfuly deleted the port {0}'.format(port_id))

    subnet = _get_or_create_subnet(container_info, neutron_network_id)
    neutron_subnet_id = subnet['id']

    router = _get_or_create_router(GLOBAL_ROUTER_NAME)
    neutron_router_id = router['id']

    filtered_ports = _get_ports_by_attrs(
        unique=False, device_owner='network:router_interface',
        device_id=neutron_router_id, network_id=neutron_network_id)

    router_ports = _get_router_ports_by_subnet_id(neutron_subnet_id, filtered_ports)

    if len(router_ports) == 1:
        neutron.remove_interface_router(
            neutron_router_id, {'subnet_id': neutron_subnet_id})
        logger.debug('The subnet {0} is unbound from the router {1}'
                     .format(neutron_subnet_id, neutron_router_id))

    try:
        neutron.delete_subnet(neutron_subnet_id)
        logger.debug('Deleted the subnet {0}'.format(neutron_subnet_id))
    except n_exceptions.Conflict as ex:
        logger.info('The subnet {0} is still in use.'
                    .format(neutron_subnet_id))

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
    network_name = pod_namespace + get_hostname()
    filtered_networks = _get_networks_by_attrs(name=network_name)
    if not filtered_networks:
        return
    network = filtered_networks[0]
    neutron_network_id = network['id']
    filtered_ports = _get_ports_by_attrs(
        name=pod_name, network_id=neutron_network_id)
    if not filtered_ports:
        return
    port = filtered_ports[0]
    ip_address = _get_ip_address_in_port(port)

    status_response = {
        "apiVersion": "v1beta1",
        "kind": "PodNetworkStatus",
    }
    status_response['ip'] = ip_address
    logger.debug('Sending the status of {0}, {1}: {2}'
                 .format(pod_name, network_name, status_response))

    sys.stdout.write(json.dumps(status_response))


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
