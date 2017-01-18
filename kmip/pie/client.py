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

import logging
import six

from kmip.core import enums
from kmip.core import objects as cobjects

from kmip.core.factories import attributes

from kmip.core.attributes import CryptographicParameters, \
    CryptographicAlgorithm

from kmip.pie import api
from kmip.pie import exceptions
from kmip.pie import factory
from kmip.pie import objects as pobjects

from kmip.services.kmip_client import KMIPProxy


class ProxyKmipClient(api.KmipClient):
    """
    A simplified KMIP client for conducting KMIP operations.

    The ProxyKmipClient is a simpler KMIP client supporting various KMIP
    operations. It wraps the original KMIPProxy, reducing the boilerplate
    needed to deploy PyKMIP in client applications. The underlying proxy
    client is responsible for setting up the underlying socket connection
    and for writing/reading data to/from the socket.

    Like the KMIPProxy, the ProxyKmipClient is not thread-safe.
    """
    def __init__(self,
                 hostname=None,
                 port=None,
                 cert=None,
                 key=None,
                 ca=None,
                 ssl_version=None,
                 username=None,
                 password=None,
                 config='client'):
        """
        Construct a ProxyKmipClient.

        Args:
            hostname (string): The host or IP address of a KMIP appliance.
                Optional, defaults to None.
            port (int): The port number used to establish a connection to a
                KMIP appliance. Usually 5696 for KMIP applications. Optional,
                defaults to None.
            cert (string): The path to the client's certificate. Optional,
                defaults to None.
            key (string): The path to the key for the client's certificate.
                Optional, defaults to None.
            ca (string): The path to the CA certificate used to verify the
                server's certificate. Optional, defaults to None.
            ssl_version (string): The name of the ssl version to use for the
                connection. Example: 'PROTOCOL_SSLv23'. Optional, defaults to
                None.
            username (string): The username of the KMIP appliance account to
                use for operations. Optional, defaults to None.
            password (string): The password of the KMIP appliance account to
                use for operations. Optional, defaults to None.
            config (string): The name of a section in the PyKMIP configuration
                file. Use to load a specific set of configuration settings from
                the configuration file, instead of specifying them manually.
                Optional, defaults to the default client section, 'client'.
        """
        self.logger = logging.getLogger()

        self.attribute_factory = attributes.AttributeFactory()
        self.object_factory = factory.ObjectFactory()

        # TODO (peter-hamilton) Consider adding validation checks for inputs.
        self.proxy = KMIPProxy(
            host=hostname,
            port=port,
            certfile=cert,
            keyfile=key,
            ca_certs=ca,
            ssl_version=ssl_version,
            username=username,
            password=password,
            config=config)

        # TODO (peter-hamilton) Add a multiprocessing lock for synchronization.
        self._is_open = False

    def open(self):
        """
        Open the client connection.

        Raises:
            ClientConnectionFailure: if the client connection is already open
            Exception: if an error occurs while trying to open the connection
        """
        if self._is_open:
            raise exceptions.ClientConnectionFailure(
                "client connection already open")
        else:
            try:
                self.proxy.open()
                self._is_open = True
            except Exception as e:
                self.logger.exception("could not open client connection", e)
                raise e

    def close(self):
        """
        Close the client connection.

        Raises:
            ClientConnectionNotOpen: if the client connection is not open
            Exception: if an error occurs while trying to close the connection
        """
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()
        else:
            try:
                self.proxy.close()
                self._is_open = False
            except Exception as e:
                self.logger.exception("could not close client connection", e)
                raise e

    def create(self, algorithm, length, operation_policy_name=None, name=None):
        """
        Create a symmetric key on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the symmetric key.
            length (int): The length in bits for the symmetric key.
            operation_policy_name (string): The name of the operation policy
                to use for the new symmetric key. Optional, defaults to None
            name (string): The name to give the key. Optional, defaults to None

        Returns:
            string: The uid of the newly created symmetric key.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        # Check inputs
        if not isinstance(algorithm, enums.CryptographicAlgorithm):
            raise TypeError(
                "algorithm must be a CryptographicAlgorithm enumeration")
        elif not isinstance(length, six.integer_types) or length <= 0:
            raise TypeError("length must be a positive integer")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        # Create the template containing the attributes
        common_attributes = self._build_common_attributes(
            operation_policy_name
        )
        key_attributes = self._build_key_attributes(algorithm, length)
        key_attributes.extend(common_attributes)

        if name:
            key_attributes.extend(self._build_name_attribute(name))

        template = cobjects.TemplateAttribute(attributes=key_attributes)

        # Create the symmetric key and handle the results
        result = self.proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            uid = result.uuid.value
            return uid
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def create_key_pair(self,
                        algorithm,
                        length,
                        operation_policy_name=None,
                        public_name=None,
                        private_name=None):
        """
        Create an asymmetric key pair on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the key pair.
            length (int): The length in bits for the key pair.
            operation_policy_name (string): The name of the operation policy
                to use for the new key pair. Optional, defaults to None.
            public_name (string): The name to give the public key.
                                  Optional, defaults to None.
            private_name (string): The name to give the public key.
                                   Optional, defaults to None.

        Returns:
            string: The uid of the newly created public key.
            string: The uid of the newly created private key.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        # Check inputs
        if not isinstance(algorithm, enums.CryptographicAlgorithm):
            raise TypeError(
                "algorithm must be a CryptographicAlgorithm enumeration")
        elif not isinstance(length, six.integer_types) or length <= 0:
            raise TypeError("length must be a positive integer")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        # Create the common attributes that are shared
        common_attributes = self._build_common_attributes(
            operation_policy_name
        )
        key_attributes = self._build_key_attributes(algorithm, length)
        key_attributes.extend(common_attributes)
        template = cobjects.CommonTemplateAttribute(attributes=key_attributes)

        # Create public / private specific attributes
        public_template = None
        if public_name:
            name_attr = self._build_name_attribute(name=public_name)
            public_template = cobjects.PublicKeyTemplateAttribute(
                names=name_attr
            )

        private_template = None
        if private_name:
            name_attr = self._build_name_attribute(name=private_name)
            private_template = cobjects.PrivateKeyTemplateAttribute(
                names=name_attr
            )

        # Create the asymmetric key pair and handle the results
        result = self.proxy.create_key_pair(
            common_template_attribute=template,
            private_key_template_attribute=private_template,
            public_key_template_attribute=public_template)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            public_uid = result.public_key_uuid.value
            private_uid = result.private_key_uuid.value
            return public_uid, private_uid
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def register(self, managed_object):
        """
        Register a managed object with a KMIP appliance.

        Args:
            managed_object (ManagedObject): A managed object to register. An
                instantiatable subclass of ManagedObject from the Pie API.

        Returns:
            string: The uid of the newly registered managed object.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if not isinstance(managed_object, pobjects.ManagedObject):
            raise TypeError("managed object must be a Pie ManagedObject")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        # Extract and create attributes
        object_attributes = list()

        if hasattr(managed_object, 'cryptographic_usage_masks'):
            if managed_object.cryptographic_usage_masks is not None:
                mask_attribute = self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    managed_object.cryptographic_usage_masks
                )
                object_attributes.append(mask_attribute)
        if hasattr(managed_object, 'operation_policy_name'):
            if managed_object.operation_policy_name is not None:
                opn_attribute = self.attribute_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    managed_object.operation_policy_name
                )
                object_attributes.append(opn_attribute)

        template = cobjects.TemplateAttribute(attributes=object_attributes)
        object_type = managed_object.object_type

        # Register the managed object and handle the results
        secret = self.object_factory.convert(managed_object)
        result = self.proxy.register(object_type, template, secret)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            uid = result.uuid.value
            return uid
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def get(self, uid):
        """
        Get a managed object from a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to retrieve.

        Returns:
            ManagedObject: The retrieved managed object object.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if not isinstance(uid, six.string_types):
            raise TypeError("uid must be a string")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        # Get the managed object and handle the results
        result = self.proxy.get(uid)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            managed_object = self.object_factory.convert(result.secret)
            return managed_object
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def get_attributes(self, uid=None, attribute_names=None):
        """
        Get the attributes associated with a managed object.

        If the uid is not specified, the appliance will use the ID placeholder
        by default.

        If the attribute_names list is not specified, the appliance will
        return all viable attributes for the managed object.

        Args:
            uid (string): The unique ID of the managed object with which the
                retrieved attributes should be associated. Optional, defaults
                to None.
            attribute_names (list): A list of string attribute names
                indicating which attributes should be retrieved. Optional,
                defaults to None.
        """
        # Check input
        if uid is not None:
            if not isinstance(uid, six.string_types):
                raise TypeError("uid must be a string")
        if attribute_names is not None:
            if not isinstance(attribute_names, list):
                raise TypeError("attribute_names must be a list of strings")
            else:
                for attribute_name in attribute_names:
                    if not isinstance(attribute_name, six.string_types):
                        raise TypeError(
                            "attribute_names must be a list of strings"
                        )

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        # Get the list of attributes for a managed object
        result = self.proxy.get_attributes(uid, attribute_names)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return result.uuid, result.attributes
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def get_attribute_list(self, uid=None):
        """
        Get the names of the attributes associated with a managed object.

        If the uid is not specified, the appliance will use the ID placeholder
        by default.

        Args:
            uid (string): The unique ID of the managed object with which the
                retrieved attribute names should be associated. Optional,
                defaults to None.
        """
        # Check input
        if uid is not None:
            if not isinstance(uid, six.string_types):
                raise TypeError("uid must be a string")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        # Get the list of attribute names for a managed object.
        result = self.proxy.get_attribute_list(uid)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            attribute_names = sorted(result.names)
            return attribute_names
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def destroy(self, uid):
        """
        Destroy a managed object stored by a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to destroy.

        Returns:
            None

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if not isinstance(uid, six.string_types):
            raise TypeError("uid must be a string")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        # Destroy the managed object and handle the results
        result = self.proxy.destroy(uid)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def mac(self, uid, algorithm, data):
        """
        Get the message authentication code for data.

        Args:
            uid (string): The unique ID of the managed object that is the key
                to use for the MAC operation.
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the MAC.
            data (string): The data to be MACed.


        Returns:
            string: The unique ID of the managed object that is the key
                to use for the MAC operation.
            string: The data MACed

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        # Check inputs
        if not isinstance(uid, six.string_types):
            raise TypeError("uid must be a string")
        if not isinstance(algorithm, enums.CryptographicAlgorithm):
            raise TypeError(
                "algorithm must be a CryptographicAlgorithm enumeration")
        if not isinstance(data, six.binary_type):
            raise TypeError(
                "data must be bytes")

        # Verify that operations can be given at this time
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()

        parameters_attribute = CryptographicParameters(
            cryptographic_algorithm=CryptographicAlgorithm(algorithm))

        # Create the symmetric key and handle the results
        result = self.proxy.mac(uid, parameters_attribute, data)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            uid = result.uuid.value
            mac_data = result.mac_data.value
            return uid, mac_data
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def _build_key_attributes(self, algorithm, length):
        # Build a list of core key attributes.
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            length)
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            [enums.CryptographicUsageMask.ENCRYPT,
             enums.CryptographicUsageMask.DECRYPT])

        return [algorithm_attribute, length_attribute, mask_attribute]

    def _build_common_attributes(self, operation_policy_name=None):
        '''
         Build a list of common attributes that are shared across
         symmetric as well as asymmetric objects
        '''
        common_attributes = []

        if operation_policy_name:
            common_attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.OPERATION_POLICY_NAME,
                    operation_policy_name
                )
            )

        return common_attributes

    def _build_name_attribute(self, name=None):
        '''
        Build a name attribute, returned in a list for ease
        of use in the caller
        '''
        name_list = []
        if name:
            name_list.append(self.attribute_factory.create_attribute(
                enums.AttributeType.NAME,
                name)
            )
        return name_list

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
