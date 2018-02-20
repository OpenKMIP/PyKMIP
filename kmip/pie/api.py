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
    def locate(self, maximum_items, storage_status_mask, object_group_member,
               attributes):
        """
        Search for managed objects with a KMIP appliance.

        Args:
            maximum_items (integer): Maximum number of object identifiers the
                server MAY return.
            storage_status_mask (integer): A bit mask that indicates whether
                on-line or archived objects are to be searched.
            object_group_member (ObjectGroupMember): An enumeration that
                indicates the object group member type.
            attributes (list): Attributes the are REQUIRED to match those in a
                candidate object.

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
    def activate(self, uid):
        """
        Activate a managed object stored by a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to activate.
        """
        pass

    @abc.abstractmethod
    def revoke(self, revocation_reason, uid, revocation_message,
               compromise_occurrence_date):
        """
        Revoke a managed object stored by a KMIP appliance.

        Args:
            revocation_reason (RevocationReasonCode): An enumeration indicating
                the revocation reason.
            uid (string): The unique ID of the managed object to revoke.
                Optional, defaults to None.
            revocation_message (string): A message regarding the revocation.
                Optional, defaults to None.
            compromise_occurrence_date (int): A integer which will be converted
                to the Datetime when the managed object was firstly believed to
                be compromised. Optional, defaults to None.
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
    def encrypt(self, data, uid=None, cryptographic_parameters=None,
                iv_counter_nonce=None):
        """
        Encrypt data using the specified encryption key and parameters.

        Args:
            data (bytes): The bytes to encrypt. Required.
            uid (string): The unique ID of the encryption key to use.
                Optional, defaults to None.
            cryptographic_parameters (dict): A dictionary containing various
                cryptographic settings to be used for the encryption.
                Optional, defaults to None.
            iv_counter_nonce (bytes): The bytes to use for the IV/counter/
                nonce, if needed by the encryption algorithm and/or cipher
                mode. Optional, defaults to None.
        """
        pass

    @abc.abstractmethod
    def decrypt(self, data, uid=None, cryptographic_parameters=None,
                iv_counter_nonce=None):
        """
        Decrypt data using the specified decryption key and parameters.

        Args:
            data (bytes): The bytes to decrypt. Required.
            uid (string): The unique ID of the decryption key to use.
                Optional, defaults to None.
            cryptographic_parameters (dict): A dictionary containing various
                cryptographic settings to be used for the decryption.
                Optional, defaults to None.
            iv_counter_nonce (bytes): The bytes to use for the IV/counter/
                nonce, if needed by the decryption algorithm and/or cipher
                mode. Optional, defaults to None.
        """
        pass

    @abc.abstractmethod
    def mac(self, data, uid, algorithm):
        """
        Get the message authentication code for data.

        Args:
            data (string): The data to be MACed.
            uid (string): The unique ID of the managed object that is the key
                to use for the MAC operation.
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the MAC.
        """
        pass
