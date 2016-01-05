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


class MidoNetPluginException(Exception):
    """Default Kuryr exception"""


class BindingFailure(MidoNetPluginException):
    """Exception represents the binding is failed.

    This exception is thrown when the executable script for the binding is
    failed and Kuryr can't proceed further.
    """


class DuplicatedResourceException(MidoNetPluginException):
    """Exception represents there're multiple resources for the ID.

    For example, this exception is thrown when you query the Neutron resource
    associated with the ID and you get multiple resources.
    """


class MandatoryApiMissing(MidoNetPluginException):
    """Exception represents that mandatory api is not found.

    For example, this exception is thrown when expected neutron
    extension(subnetpools) APIs are not found.
    """


class NoResourceException(MidoNetPluginException):
    """Exception represents there's no resource for the given query.

    This exception is thrown when you query the Neutron resource associated
    with the given query and you get none of them actually.
    """


class VethCreationFailure(MidoNetPluginException):
    """Exception represents the veth pair creation is failed.

    This exception is thrown when the veth pair is not created appropriately
    and Kuryr can't proceed the binding further.
    """


class VethDeletionFailure(MidoNetPluginException):
    """Exception represents the veth pair deletion is failed.

    This exception is thrown when the veth pair is not deleted appropriately
    and Kuryr can't proceed the unbinding further.
    """
