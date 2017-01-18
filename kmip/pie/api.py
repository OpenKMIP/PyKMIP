# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class KmipClient:
    """
    A simplified KMIP client interface for conducting KMIP operations.

    The KmipClient provides a simple external interface for various KMIP
    operations and composes the bulk of the PyKMIP Pie API.
    """
    @abc.abstractmethod
    def create(self, algorithm, length):
        """
        Create a symmetric key on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the symmetric key.
            length (int): The length in bits for the symmetric key.
        """
        pass

    @abc.abstractmethod
    def create_key_pair(self, algorithm, length):
        """
        Create an asymmetric key pair on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the key pair.
            length (int): The length in bits for the key pair.
        """
        pass

    @abc.abstractmethod
    def register(self, managed_object):
        """
        Register a managed object with a KMIP appliance.

        Args:
            managed_object (ManagedObject): A managed object to register. An
                instantiatable subclass of ManagedObject from the Pie API.
        """
        pass

    @abc.abstractmethod
    def get(self, uid):
        """
        Get a managed object from a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to retrieve.
        """
        pass

    @abc.abstractmethod
    def get_attribute_list(self, uid):
        """
        Get a list of attribute names for a managed object on a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object whose attribute
                names should be retrieved.
        """
        pass

    @abc.abstractmethod
    def destroy(self, uid):
        """
        Destroy a managed object stored by a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to destroy.
        """
        pass

    @abc.abstractmethod
    def mac(self, uid, algorithm, data):
        """
        Get the message authentication code for data.

        Args:
            uid (string): The unique ID of the managed object that is the key
                to use for the MAC operation.
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the MAC.
            data (string): The data to be MACed.
        """
        pass
