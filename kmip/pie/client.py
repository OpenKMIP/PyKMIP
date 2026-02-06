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

from kmip.core import enums
from kmip.core import primitives
from kmip.core import objects as cobjects

from kmip.core.factories import attributes

from kmip.core.attributes import CryptographicParameters
from kmip.core.attributes import DerivationParameters

from kmip.core.messages import payloads

from kmip.pie import exceptions
from kmip.pie import factory
from kmip.pie import objects as pobjects

from kmip.services.kmip_client import KMIPProxy

def is_connected(function):
    def wrapper(self, *args, **kwargs):
        if not self._is_open:
            raise exceptions.ClientConnectionNotOpen()
        return function(self, *args, **kwargs)
    return wrapper

class ProxyKmipClient(object):
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
                 config='client',
                 config_file=None,
                 kmip_version=None):
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
            config_file (string): The path to the client's configuration file.
                Optional, defaults to None.
            kmip_version (KMIPVersion): The KMIP version the client should use
                when making requests. Optional, defaults to None. If None at
                request time, the client will use KMIP 1.2.

        """
        self.logger = logging.getLogger(__name__)

        self.attribute_factory = attributes.AttributeFactory()
        self.attribute_value_factory = self.attribute_factory.value_factory
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
            config=config,
            config_file=config_file,
            kmip_version=kmip_version
        )

        # TODO (peter-hamilton) Add a multiprocessing lock for synchronization.
        self._is_open = False

    @property
    def kmip_version(self):
        """
        Get the KMIP version for the client.

        Return:
            kmip_version (KMIPVersion): The KMIPVersion enumeration used by
                the client for KMIP requests.
        """
        return self.proxy.kmip_version

    @kmip_version.setter
    def kmip_version(self, value):
        """
        Set the KMIP version for the client.

        Args:
            value (KMIPVersion): A KMIPVersion enumeration

        Return:
            None

        Raises:
            ValueError: if value is not a KMIPVersion enumeration

        Example:
            >>> client.kmip_version = enums.KMIPVersion.KMIP_1_1
            >>>
        """
        if isinstance(value, enums.KMIPVersion):
            self.proxy.kmip_version = value
        else:
            raise ValueError("KMIP version must be a KMIPVersion enumeration")

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
                self.logger.error("could not open client connection: %s", e)
                raise

    def close(self):
        """
        Close the client connection.

        Raises:
            Exception: if an error occurs while trying to close the connection
        """
        if not self._is_open:
            return
        else:
            try:
                self.proxy.close()
                self._is_open = False
            except Exception as e:
                self.logger.error("could not close client connection: %s", e)
                raise

    @is_connected
    def create(self, algorithm, length, operation_policy_name=None, name=None, cryptographic_usage_mask=None):
        """
        Create a symmetric key on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the symmetric key.
            length (int): The length in bits for the symmetric key.
            operation_policy_name (string): The name of the operation policy
                to use for the new symmetric key. Optional, defaults to None
            name (string): The name to give the key. Optional, defaults to None
            cryptographic_usage_mask (list): list of enumerations of crypto
                usage mask passing to the symmetric key. Optional, defaults to
                None

        Returns:
            string: The uid of the newly created symmetric key.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """

        # Check inputs
        # TODO (peter-hamilton) Add better input validation checks.
        from kmip.core.enums import CryptographicAlgorithm as CoreAlgorithm

        if not (
        isinstance(algorithm, enums.CryptographicAlgorithm) or isinstance(algorithm, CoreAlgorithm)
        ):
            raise TypeError(
                f"algorithm must be a CryptographicAlgorithm enumeration, got {type(algorithm)}"
            )
    

        #if not isinstance(algorithm, enums.CryptographicAlgorithm):
        #    raise TypeError(
        #        "algorithm must be a CryptographicAlgorithm enumeration")
        
        elif not isinstance(length, int) or length <= 0:
            raise TypeError("length must be a positive integer")
        if cryptographic_usage_mask is not None:
            if not isinstance(cryptographic_usage_mask, list) or \
                all(isinstance(item, enums.CryptographicUsageMask)
                    for item in cryptographic_usage_mask) is False:
                raise TypeError(
                    "cryptographic_usage_mask must be a list of "
                    "CryptographicUsageMask enumerations")

        # Create the template containing the attributes
        common_attributes = self._build_common_attributes(
            operation_policy_name
        )
        key_attributes = self._build_key_attributes(
                            algorithm, length, cryptographic_usage_mask)
        key_attributes.extend(common_attributes)

        if name:
            key_attributes.extend(
                [
                    self.attribute_factory.create_attribute(
                        enums.AttributeType.NAME,
                        name
                    )
                ]
            )

        template = cobjects.TemplateAttribute(attributes=key_attributes)

        # Create the symmetric key and handle the results
        result = self.proxy.create(enums.ObjectType.SYMMETRIC_KEY, template)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return result.uuid
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
    def create_key_pair(self,
                        algorithm,
                        length,
                        operation_policy_name=None,
                        public_name=None,
                        public_usage_mask=None,
                        private_name=None,
                        private_usage_mask=None):
        """
        Create an asymmetric key pair on a KMIP appliance.

        Args:
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the key pair.
            length (int): The length in bits for the key pair.
            operation_policy_name (string): The name of the operation policy
                to use for the new key pair. Optional, defaults to None.
            public_name (string): The name to give the public key. Optional,
                defaults to None.
            public_usage_mask (list): A list of CryptographicUsageMask
                enumerations indicating how the public key should be used.
                Optional, defaults to None.
            private_name (string): The name to give the public key. Optional,
                defaults to None.
            private_usage_mask (list): A list of CryptographicUsageMask
                enumerations indicating how the private key should be used.
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
        elif not isinstance(length, int) or length <= 0:
            raise TypeError("length must be a positive integer")

        # Create the common attributes that are shared
        common_attributes = self._build_common_attributes(
            operation_policy_name
        )

        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            algorithm
        )
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            length
        )

        common_attributes.extend([algorithm_attribute, length_attribute])
        template = cobjects.TemplateAttribute(
            attributes=common_attributes,
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE
        )

        # Create public / private specific attributes
        public_template = None
        attrs = []
        if public_name:
            attrs.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    public_name
                )
            )
        if public_usage_mask:
            attrs.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    public_usage_mask
                )
            )
        if attrs:
            public_template = cobjects.TemplateAttribute(
                attributes=attrs,
                tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE
            )

        private_template = None
        attrs = []
        if private_name:
            attrs.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.NAME,
                    private_name
                )
            )
        if private_usage_mask:
            attrs.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    private_usage_mask
                )
            )
        if attrs:
            private_template = cobjects.TemplateAttribute(
                attributes=attrs,
                tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE
            )

        # Create the asymmetric key pair and handle the results
        result = self.proxy.create_key_pair(
            common_template_attribute=template,
            private_key_template_attribute=private_template,
            public_key_template_attribute=public_template)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            public_uid = result.public_key_uuid
            private_uid = result.private_key_uuid
            return public_uid, private_uid
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
    def delete_attribute(self, unique_identifier=None, **kwargs):
        """
        Delete an attribute from a KMIP managed object.

        Args:
            unique_identifier (string): The ID of the managed object.
            **kwargs (various): A placeholder for attribute values used to
                identify the attribute to delete. For KMIP 1.0 - 1.4, the
                supported parameters are:
                    attribute_name (string): The name of the attribute to
                        delete. Required.
                    attribute_index (int): The index of the attribute to
                        delete. Defaults to zero.
                For KMIP 2.0+, the supported parameters are:
                    current_attribute (struct): A CurrentAttribute object
                        containing the attribute to delete. Required if the
                        attribute reference is not specified.
                    attribute_reference (struct): An AttributeReference
                        object containing the name of the attribute to
                        delete. Required if the current attribute  is not
                        specified.

        Returns:
            string: The ID of the managed object the attribute was deleted
                from.
            struct: A Primitive object representing the deleted attribute.
                Only returned if used for KMIP 1.0 - 1.4 messages.
        """
        request_payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier=unique_identifier,
            attribute_name=kwargs.get("attribute_name"),
            attribute_index=kwargs.get("attribute_index"),
            current_attribute=kwargs.get("current_attribute"),
            attribute_reference=kwargs.get("attribute_reference")
        )
        response_payload = self.proxy.send_request_payload(
            enums.Operation.DELETE_ATTRIBUTE,
            request_payload
        )

        return response_payload.unique_identifier, response_payload.attribute

    @is_connected
    def set_attribute(self, unique_identifier=None, **kwargs):
        """
        Set an attribute on a KMIP managed object.

        Args:
            unique_identifier (string): The ID of the managed object.
            **kwargs (various): A placeholder for attribute-related fields.
                Supported parameters include:
                    attribute_name (string): The name of the attribute being
                        set. Required.
                    attribute_value (various): The value of the attribute
                        being set. Required.

                Here is an example. To set an object's 'sensitive' attribute
                to True, specify:
                    attribute_name='Sensitive'
                    attribute_value=True

                For a list of all supported attributes, see the
                AttributeValueFactory.

        Returns:
            string: The ID of the managed object the attribute was set on.
        """
        a = self.attribute_value_factory.create_attribute_value_by_enum(
            enums.convert_attribute_name_to_tag(kwargs.get("attribute_name")),
            kwargs.get("attribute_value")
        )
        request_payload = payloads.SetAttributeRequestPayload(
            unique_identifier=unique_identifier,
            new_attribute=cobjects.NewAttribute(attribute=a)
        )
        response_payload = self.proxy.send_request_payload(
            enums.Operation.SET_ATTRIBUTE,
            request_payload
        )

        return response_payload.unique_identifier

    @is_connected
    def modify_attribute(self, unique_identifier=None, **kwargs):
        """
        Set an attribute on a KMIP managed object.

        Args:
            unique_identifier (string): The ID of the managed object.
            **kwargs (various): A placeholder for attribute values used to
                identify the attribute to modify. For KMIP 1.0 - 1.4, the
                supported parameters are:
                    attribute (struct): An Attribute object containing the
                        name and index of the existing attribute and the
                        new value for that attribute.
                For KMIP 2.0+, the supported parameters are:
                    current_attribute (struct): A CurrentAttribute object
                        containing the attribute to modify. Required if the
                        attribute is multivalued.
                    attribute_reference (struct): A NewAttribute object
                        containing the new attribute value. Required.

        Returns:
            string: The ID of the managed object the attribute was modified on.
            struct: An Attribute object representing the newly modified
                attribute. Only returned if used for KMIP 1.0 - 1.4 messages.
        """
        request_payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier=unique_identifier,
            attribute=kwargs.get("attribute"),
            current_attribute=kwargs.get("current_attribute"),
            new_attribute=kwargs.get("new_attribute")
        )
        response_payload = self.proxy.send_request_payload(
            enums.Operation.MODIFY_ATTRIBUTE,
            request_payload
        )

        return response_payload.unique_identifier, response_payload.attribute

    @is_connected
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
        if hasattr(managed_object, 'names'):
            if managed_object.names:
                for name in managed_object.names:
                    name_attribute = self.attribute_factory.create_attribute(
                        enums.AttributeType.NAME,
                        name
                    )
                    object_attributes.append(name_attribute)

        if hasattr(managed_object, '_application_specific_informations'):
            if managed_object._application_specific_informations:
                for info in managed_object._application_specific_informations:
                    attribute = self.attribute_factory.create_attribute(
                        enums.AttributeType.APPLICATION_SPECIFIC_INFORMATION,
                        info,
                        index=0
                    )
                    object_attributes.append(attribute)
        template = cobjects.TemplateAttribute(attributes=object_attributes)
        object_type = managed_object.object_type
        # Register the managed object and handle the results
        secret = self.object_factory.convert(managed_object)
        result = self.proxy.register(object_type, template, secret)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return result.uuid
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
    def rekey(self,
              uid=None,
              offset=None,
              **kwargs):
        """
        Rekey an existing key.

        Args:
            uid (string): The unique ID of the symmetric key to rekey.
                Optional, defaults to None.
            offset (int): The time delta, in seconds, between the new key's
                initialization date and activation date. Optional, defaults
                to None.
            **kwargs (various): A placeholder for object attributes that
                should be set on the newly rekeyed key. Currently
                supported attributes include:
                    activation_date (int)
                    process_start_date (int)
                    protect_stop_date (int)
                    deactivation_date (int)

        Returns:
            string: The unique ID of the newly rekeyed key.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("The unique identifier must be a string.")
        if offset is not None:
            if not isinstance(offset, int):
                raise TypeError("The offset must be an integer.")

        # TODO (peter-hamilton) Unify attribute handling across operations
        attributes = []
        if kwargs.get('activation_date'):
            attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.ACTIVATION_DATE,
                    kwargs.get('activation_date')
                )
            )
        if kwargs.get('process_start_date'):
            attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.PROCESS_START_DATE,
                    kwargs.get('process_start_date')
                )
            )
        if kwargs.get('protect_stop_date'):
            attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.PROTECT_STOP_DATE,
                    kwargs.get('protect_stop_date')
                )
            )
        if kwargs.get('deactivation_date'):
            attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.DEACTIVATION_DATE,
                    kwargs.get('deactivation_date')
                )
            )
        template_attribute = cobjects.TemplateAttribute(
            attributes=attributes
        )

        # Derive the new key/data and handle the results
        result = self.proxy.rekey(
            uuid=uid,
            offset=offset,
            template_attribute=template_attribute
        )

        status = result.get('result_status')
        if status == enums.ResultStatus.SUCCESS:
            return result.get('unique_identifier')
        else:
            raise exceptions.KmipOperationFailure(
                status,
                result.get('result_reason'),
                result.get('result_message')
            )

    @is_connected
    def derive_key(self,
                   object_type,
                   unique_identifiers,
                   derivation_method,
                   derivation_parameters,
                   **kwargs):
        """
        Derive a new key or secret data from existing managed objects.

        Args:
            object_type (ObjectType): An ObjectType enumeration specifying
                what type of object to derive. Only SymmetricKeys and
                SecretData can be specified. Required.
            unique_identifiers (list): A list of strings specifying the
                unique IDs of the existing managed objects to use for
                derivation. Multiple objects can be specified to fit the
                requirements of the given derivation method. Required.
            derivation_method (DerivationMethod): A DerivationMethod
                enumeration specifying how key derivation should be done.
                Required.
            derivation_parameters (dict): A dictionary containing various
                settings for the key derivation process. See Note below.
                Required.
            **kwargs (various): A placeholder for object attributes that
                should be set on the newly derived object. Currently
                supported attributes include:
                    cryptographic_algorithm (enums.CryptographicAlgorithm)
                    cryptographic_length (int)

        Returns:
            string: The unique ID of the newly derived object.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid

        Notes:
            The derivation_parameters argument is a dictionary that can
            contain the following key/value pairs:

            Key                        | Value
            ---------------------------|---------------------------------------
            'cryptographic_parameters' | A dictionary containing additional
                                       | cryptographic settings. See the
                                       | decrypt method for more information.
            'initialization_vector'    | Bytes to be used to initialize the key
                                       | derivation function, if needed.
            'derivation_data'          | Bytes to be used as the basis for the
                                       | key derivation process (e.g., the
                                       | bytes to be encrypted, hashed, etc).
            'salt'                     | Bytes to used as a salt value for the
                                       | key derivation function, if needed.
                                       | Usually used with PBKDF2.
            'iteration_count'          | An integer defining how many
                                       | iterations should be used with the key
                                       | derivation function, if needed.
                                       | Usually used with PBKDF2.
        """
        # Check input
        if not isinstance(object_type, enums.ObjectType):
            raise TypeError("Object type must be an ObjectType enumeration.")
        if not isinstance(unique_identifiers, list):
            raise TypeError("Unique identifiers must be a list of strings.")
        else:
            for unique_identifier in unique_identifiers:
                if not isinstance(unique_identifier, str):
                    raise TypeError(
                        "Unique identifiers must be a list of strings."
                    )
        if not isinstance(derivation_method, enums.DerivationMethod):
            raise TypeError(
                "Derivation method must be a DerivationMethod enumeration."
            )
        if not isinstance(derivation_parameters, dict):
            raise TypeError("Derivation parameters must be a dictionary.")

        derivation_parameters = DerivationParameters(
            cryptographic_parameters=self._build_cryptographic_parameters(
                derivation_parameters.get('cryptographic_parameters')
            ),
            initialization_vector=derivation_parameters.get(
                'initialization_vector'
            ),
            derivation_data=derivation_parameters.get('derivation_data'),
            salt=derivation_parameters.get('salt'),
            iteration_count=derivation_parameters.get('iteration_count')
        )

        # Handle object attributes
        attributes = []
        if kwargs.get('cryptographic_length'):
            attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                    kwargs.get('cryptographic_length')
                )
            )
        if kwargs.get('cryptographic_algorithm'):
            attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                    kwargs.get('cryptographic_algorithm')
                )
            )
        if kwargs.get('cryptographic_usage_mask'):
            attributes.append(
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    kwargs.get('cryptographic_usage_mask')
                )
            )
        template_attribute = cobjects.TemplateAttribute(
            attributes=attributes
        )

        # Derive the new key/data and handle the results
        result = self.proxy.derive_key(
            object_type,
            unique_identifiers,
            derivation_method,
            derivation_parameters,
            template_attribute
        )

        status = result.get('result_status')
        if status == enums.ResultStatus.SUCCESS:
            return result.get('unique_identifier')
        else:
            raise exceptions.KmipOperationFailure(
                status,
                result.get('result_reason'),
                result.get('result_message')
            )

    @is_connected
    def locate(self, maximum_items=None, storage_status_mask=None,
               object_group_member=None, attributes=None, offset_items=None):
        """
        Search for managed objects, depending on the attributes specified in
        the request.

        Args:
            maximum_items (integer): Maximum number of object identifiers the
                server MAY return.
            offset_items (integer): Number of object identifiers the server
                should skip before returning results.
            storage_status_mask (integer): A bit mask that indicates whether
                on-line or archived objects are to be searched.
            object_group_member (ObjectGroupMember): An enumeration that
                indicates the object group member type.
            attributes (list): Attributes the are REQUIRED to match those in a
                candidate object.

        Returns:
            list: The Unique Identifiers of the located objects

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        # Check inputs
        if maximum_items is not None:
            if not isinstance(maximum_items, int):
                raise TypeError("maximum_items must be an integer")
        if offset_items is not None:
            if not isinstance(offset_items, int):
                raise TypeError("offset items must be an integer")
        if storage_status_mask is not None:
            if not isinstance(storage_status_mask, int):
                raise TypeError("storage_status_mask must be an integer")
        if object_group_member is not None:
            if not isinstance(object_group_member, enums.ObjectGroupMember):
                raise TypeError(
                    "object_group_member must be a ObjectGroupMember"
                    "enumeration")
        if attributes is not None:
            if not isinstance(attributes, list) or \
                all(isinstance(item, cobjects.Attribute)
                    for item in attributes) is False:
                raise TypeError(
                    "attributes must be a list of attributes")

        # Search for managed objects and handle the results
        result = self.proxy.locate(
            maximum_items=maximum_items,
            offset_items=offset_items,
            storage_status_mask=storage_status_mask,
            object_group_member=object_group_member,
            attributes=attributes
        )

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return result.uuids
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
    def check(self,
              uid=None,
              usage_limits_count=None,
              cryptographic_usage_mask=None,
              lease_time=None):
        """
        Check the constraints for a managed object.

        Args:
            uid (string): The unique ID of the managed object to check.
                Optional, defaults to None.
            usage_limits_count (int): The number of items that can be secured
                with the specified managed object. Optional, defaults to None.
            cryptographic_usage_mask (list): A list of CryptographicUsageMask
                enumerations specifying the operations possible with the
                specified managed object. Optional, defaults to None.
            lease_time (int): The number of seconds that can be leased for the
                specified managed object. Optional, defaults to None.
        """
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("The unique identifier must be a string.")
        if usage_limits_count is not None:
            if not isinstance(usage_limits_count, int):
                raise TypeError("The usage limits count must be an integer.")
        if cryptographic_usage_mask is not None:
            if not isinstance(cryptographic_usage_mask, list) or \
                    not all(isinstance(
                        x,
                        enums.CryptographicUsageMask
                    ) for x in cryptographic_usage_mask):
                raise TypeError(
                    "The cryptographic usage mask must be a list of "
                    "CryptographicUsageMask enumerations."
                )
        if lease_time is not None:
            if not isinstance(lease_time, int):
                raise TypeError("The lease time must be an integer.")

        result = self.proxy.check(
            uid,
            usage_limits_count,
            cryptographic_usage_mask,
            lease_time
        )

        status = result.get('result_status')
        if status == enums.ResultStatus.SUCCESS:
            return result.get('unique_identifier')
        else:
            raise exceptions.KmipOperationFailure(
                status,
                result.get('result_reason'),
                result.get('result_message')
            )

    @is_connected
    def get(self, uid=None, key_wrapping_specification=None):
        """
        Get a managed object from a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to retrieve.
            key_wrapping_specification (dict): A dictionary containing various
                settings to be used when wrapping the key during retrieval.
                See Note below. Optional, defaults to None.

        Returns:
            ManagedObject: The retrieved managed object object.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid

        Notes:
            The derivation_parameters argument is a dictionary that can
            contain the following key/value pairs:

            Key                             | Value
            --------------------------------|---------------------------------
            'wrapping_method'               | A WrappingMethod enumeration
                                            | that specifies how the object
                                            | should be wrapped.
            'encryption_key_information'    | A dictionary containing the ID
                                            | of the wrapping key and
                                            | associated cryptographic
                                            | parameters.
            'mac_signature_key_information' | A dictionary containing the ID
                                            | of the wrapping key and
                                            | associated cryptographic
                                            | parameters.
            'attribute_names'               | A list of strings representing
                                            | the names of attributes that
                                            | should be included with the
                                            | wrapped object.
            'encoding_option'               | An EncodingOption enumeration
                                            | that specifies the encoding of
                                            | the object before it is wrapped.
        """
        # Check input
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")
        if key_wrapping_specification is not None:
            if not isinstance(key_wrapping_specification, dict):
                raise TypeError(
                    "Key wrapping specification must be a dictionary."
                )

        spec = self._build_key_wrapping_specification(
            key_wrapping_specification
        )

        # Get the managed object and handle the results
        result = self.proxy.get(uid, key_wrapping_specification=spec)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            managed_object = self.object_factory.convert(result.secret)
            return managed_object
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
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
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")
        if attribute_names is not None:
            if not isinstance(attribute_names, list):
                raise TypeError("attribute_names must be a list of strings")
            else:
                for attribute_name in attribute_names:
                    if not isinstance(attribute_name, str):
                        raise TypeError(
                            "attribute_names must be a list of strings"
                        )

        # Get the list of attributes for a managed object
        result = self.proxy.get_attributes(uid, attribute_names)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return result.uuid, result.attributes
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
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
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")

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

    @is_connected
    def activate(self, uid=None):
        """
        Activate a managed object stored by a KMIP appliance.

        Args:
            uid (string): The unique ID of the managed object to activate.
                Optional, defaults to None.

        Returns:
            None

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")

        # Activate the managed object and handle the results
        result = self.proxy.activate(uid)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
    def revoke(self, revocation_reason, uid=None, revocation_message=None,
               compromise_occurrence_date=None):
        """
        Revoke a managed object stored by a KMIP appliance.

        Args:
            revocation_reason (RevocationReasonCode): An enumeration indicating
                the revocation reason.
            uid (string): The unique ID of the managed object to revoke.
                Optional, defaults to None.
            revocation_message (string): A message regarding the revocation.
                Optional, defaults to None.
            compromise_occurrence_date (int): An integer, the number of seconds
                since the epoch, which will be converted to the Datetime when
                the managed object was first believed to be compromised.
                Optional, defaults to None.

        Returns:
            None

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input argument is invalid
        """
        # Check input
        if not isinstance(revocation_reason, enums.RevocationReasonCode):
            raise TypeError(
                "revocation_reason must be a RevocationReasonCode enumeration")
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")
        if revocation_message is not None:
            if not isinstance(revocation_message, str):
                raise TypeError("revocation_message must be a string")
        if compromise_occurrence_date is not None:
            if not isinstance(compromise_occurrence_date, int):
                raise TypeError(
                    "compromise_occurrence_date must be an integer")
            compromise_occurrence_date = primitives.DateTime(
                compromise_occurrence_date,
                enums.Tags.COMPROMISE_OCCURRENCE_DATE)

        # revoke the managed object and handle the results
        result = self.proxy.revoke(revocation_reason, uid, revocation_message,
                                   compromise_occurrence_date)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
    def destroy(self, uid=None):
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
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")

        # Destroy the managed object and handle the results
        result = self.proxy.destroy(uid)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            return
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    @is_connected
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

        Returns:
            bytes: The encrypted data.
            bytes: The IV/counter/nonce used with the encryption algorithm,
                only if it was autogenerated by the server.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid

        Notes:
            The cryptographic_parameters argument is a dictionary that can
            contain the following key/value pairs:

            Keys                          | Value
            ------------------------------|-----------------------------------
            'block_cipher_mode'           | A BlockCipherMode enumeration
                                          | indicating the cipher mode to use
                                          | with the encryption algorithm.
            'padding_method'              | A PaddingMethod enumeration
                                          | indicating which padding method to
                                          | use with the encryption algorithm.
            'hashing_algorithm'           | A HashingAlgorithm enumeration
                                          | indicating which hashing algorithm
                                          | to use.
            'key_role_type'               | A KeyRoleType enumeration
                                          | indicating the intended use of the
                                          | associated cryptographic key.
            'digital_signature_algorithm' | A DigitalSignatureAlgorithm
                                          | enumeration indicating which
                                          | digital signature algorithm to
                                          | use.
            'cryptographic_algorithm'     | A CryptographicAlgorithm
                                          | enumeration indicating which
                                          | encryption algorithm to use.
            'random_iv'                   | A boolean indicating whether the
                                          | server should autogenerate an IV.
            'iv_length'                   | An integer representing the length
                                          | of the initialization vector (IV)
                                          | in bits.
            'tag_length'                  | An integer representing the length
                                          | of the authenticator tag in bytes.
            'fixed_field_length'          | An integer representing the length
                                          | of the fixed field portion of the
                                          | IV in bits.
            'invocation_field_length'     | An integer representing the length
                                          | of the invocation field portion of
                                          | the IV in bits.
            'counter_length'              | An integer representing the length
                                          | of the coutner portion of the IV
                                          | in bits.
            'initial_counter_value'       | An integer representing the
                                          | starting counter value for CTR
                                          | mode (typically 1).
        """
        # Check input
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")
        if cryptographic_parameters is not None:
            if not isinstance(cryptographic_parameters, dict):
                raise TypeError("cryptographic_parameters must be a dict")
        if iv_counter_nonce is not None:
            if not isinstance(iv_counter_nonce, bytes):
                raise TypeError("iv_counter_nonce must be bytes")

        cryptographic_parameters = self._build_cryptographic_parameters(
            cryptographic_parameters
        )

        # Encrypt the provided data and handle the results
        result = self.proxy.encrypt(
            data,
            uid,
            cryptographic_parameters,
            iv_counter_nonce
        )

        status = result.get('result_status')
        if status == enums.ResultStatus.SUCCESS:
            return result.get('data'), result.get('iv_counter_nonce')
        else:
            raise exceptions.KmipOperationFailure(
                status,
                result.get('result_reason'),
                result.get('result_message')
            )

    @is_connected
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

        Returns:
            bytes: The decrypted data.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid

        Notes:
            The cryptographic_parameters argument is a dictionary that can
            contain the following key/value pairs:

            Keys                          | Value
            ------------------------------|-----------------------------------
            'block_cipher_mode'           | A BlockCipherMode enumeration
                                          | indicating the cipher mode to use
                                          | with the decryption algorithm.
            'padding_method'              | A PaddingMethod enumeration
                                          | indicating which padding method to
                                          | use with the decryption algorithm.
            'hashing_algorithm'           | A HashingAlgorithm enumeration
                                          | indicating which hashing algorithm
                                          | to use.
            'key_role_type'               | A KeyRoleType enumeration
                                          | indicating the intended use of the
                                          | associated cryptographic key.
            'digital_signature_algorithm' | A DigitalSignatureAlgorithm
                                          | enumeration indicating which
                                          | digital signature algorithm to
                                          | use.
            'cryptographic_algorithm'     | A CryptographicAlgorithm
                                          | enumeration indicating which
                                          | decryption algorithm to use.
            'random_iv'                   | A boolean indicating whether the
                                          | server should autogenerate an IV.
            'iv_length'                   | An integer representing the length
                                          | of the initialization vector (IV)
                                          | in bits.
            'tag_length'                  | An integer representing the length
                                          | of the authenticator tag in bytes.
            'fixed_field_length'          | An integer representing the length
                                          | of the fixed field portion of the
                                          | IV in bits.
            'invocation_field_length'     | An integer representing the length
                                          | of the invocation field portion of
                                          | the IV in bits.
            'counter_length'              | An integer representing the length
                                          | of the counter portion of the IV
                                          | in bits.
            'initial_counter_value'       | An integer representing the
                                          | starting counter value for CTR
                                          | mode (typically 1).
        """
        # Check input
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")
        if cryptographic_parameters is not None:
            if not isinstance(cryptographic_parameters, dict):
                raise TypeError("cryptographic_parameters must be a dict")
        if iv_counter_nonce is not None:
            if not isinstance(iv_counter_nonce, bytes):
                raise TypeError("iv_counter_nonce must be bytes")

        cryptographic_parameters = self._build_cryptographic_parameters(
            cryptographic_parameters
        )

        # Decrypt the provided data and handle the results
        result = self.proxy.decrypt(
            data,
            uid,
            cryptographic_parameters,
            iv_counter_nonce
        )

        status = result.get('result_status')
        if status == enums.ResultStatus.SUCCESS:
            return result.get('data')
        else:
            raise exceptions.KmipOperationFailure(
                status,
                result.get('result_reason'),
                result.get('result_message')
            )

    @is_connected
    def signature_verify(self, message, signature, uid=None,
                         cryptographic_parameters=None):
        """
        Verify a message signature using the specified signing key.

        Args:
            message (bytes): The bytes of the signed message. Required.
            signature (bytes): The bytes of the message signature. Required.
            uid (string): The unique ID of the signing key to use.
                Optional, defaults to None.
            cryptographic_parameters (dict): A dictionary containing various
                cryptographic settings to be used for signature verification
                (e.g., cryptographic algorithm, hashing algorithm, and/or
                digital signature algorithm). Optional, defaults to None.

        Returns:
            ValidityIndicator: An enumeration indicating whether or not the
                signature was valid.

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid

        Notes:
            The cryptographic_parameters argument is a dictionary that can
            contain various key/value pairs. For a list of allowed pairs,
            see the documentation for encrypt/decrypt.
        """
        # Check input
        if not isinstance(message, bytes):
            raise TypeError("Message must be bytes.")
        if not isinstance(signature, bytes):
            raise TypeError("Signature must be bytes.")
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("Unique identifier must be a string.")
        if cryptographic_parameters is not None:
            if not isinstance(cryptographic_parameters, dict):
                raise TypeError(
                    "Cryptographic parameters must be a dictionary."
                )

        cryptographic_parameters = self._build_cryptographic_parameters(
            cryptographic_parameters
        )

        # Decrypt the provided data and handle the results
        result = self.proxy.signature_verify(
            message,
            signature,
            uid,
            cryptographic_parameters
        )

        status = result.get('result_status')
        if status == enums.ResultStatus.SUCCESS:
            return result.get('validity_indicator')
        else:
            raise exceptions.KmipOperationFailure(
                status,
                result.get('result_reason'),
                result.get('result_message')
            )

    @is_connected
    def sign(self, data, uid=None, cryptographic_parameters=None):
        """
        Create a digital signature for data using the specified signing key.

        Args:
            data (bytes): The bytes of the data to be signed. Required.
            uid (string): The unique ID of the signing key to use.
                Optional, defaults to None.
            cryptographic_parameters (dict): A dictionary containing various
                cryptographic settings to be used for creating the signature
                (e.g., cryptographic algorithm, hashing algorithm, and/or
                digital signature algorithm). Optional, defaults to None.

        Returns:
            signature (bytes): Bytes representing the signature of the data

        Raises:
            ClientConnectionNotOpen: if the client connection is unusable
            KmipOperationFailure: if the operation result is a failure
            TypeError: if the input arguments are invalid
        """
        # Check input
        if not isinstance(data, bytes):
            raise TypeError("Data to be signed must be bytes.")
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("Unique identifier must be a string.")
        if cryptographic_parameters is not None:
            if not isinstance(cryptographic_parameters, dict):
                raise TypeError(
                    "Cryptographic parameters must be a dictionary."
                )

        cryptographic_parameters = self._build_cryptographic_parameters(
            cryptographic_parameters
        )

        # Sign the provided data and handle results
        result = self.proxy.sign(
            data,
            uid,
            cryptographic_parameters
        )

        status = result.get('result_status')
        if status == enums.ResultStatus.SUCCESS:
            return result.get('signature')
        else:
            raise exceptions.KmipOperationFailure(
                status,
                result.get('result_reason'),
                result.get('result_message')
            )

    @is_connected
    def mac(self, data, uid=None, algorithm=None):
        """
        Get the message authentication code for data.

        Args:
            data (string): The data to be MACed.
            uid (string): The unique ID of the managed object that is the key
                to use for the MAC operation.
            algorithm (CryptographicAlgorithm): An enumeration defining the
                algorithm to use to generate the MAC.

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
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if uid is not None:
            if not isinstance(uid, str):
                raise TypeError("uid must be a string")
        if algorithm is not None:
            if not isinstance(algorithm, enums.CryptographicAlgorithm):
                raise TypeError(
                    "algorithm must be a CryptographicAlgorithm enumeration")

        parameters_attribute = self._build_cryptographic_parameters(
            {'cryptographic_algorithm': algorithm}
        )

        # Get the message authentication code and handle the results
        result = self.proxy.mac(data, uid, parameters_attribute)

        status = result.result_status.value
        if status == enums.ResultStatus.SUCCESS:
            uid = result.uuid.value
            mac_data = result.mac_data.value
            return uid, mac_data
        else:
            reason = result.result_reason.value
            message = result.result_message.value
            raise exceptions.KmipOperationFailure(status, reason, message)

    def _build_key_attributes(self, algorithm, length, masks=None):
        # Build a list of core key attributes.
        algorithm_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            algorithm)
        length_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
            length)
        # Default crypto usage mask value
        mask_value = [enums.CryptographicUsageMask.ENCRYPT,
                      enums.CryptographicUsageMask.DECRYPT]
        if masks:
            mask_value.extend(masks)
        # remove duplicates
        mask_value = list(set(mask_value))
        mask_attribute = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
            mask_value)

        return [algorithm_attribute, length_attribute, mask_attribute]

    def _build_cryptographic_parameters(self, value):
        """
        Build a CryptographicParameters struct from a dictionary.

        Args:
            value (dict): A dictionary containing the key/value pairs for a
                CryptographicParameters struct.

        Returns:
            None: if value is None
            CryptographicParameters: a CryptographicParameters struct

        Raises:
            TypeError: if the input argument is invalid
        """
        if value is None:
            return None
        elif not isinstance(value, dict):
            raise TypeError("Cryptographic parameters must be a dictionary.")

        cryptographic_parameters = CryptographicParameters(
            block_cipher_mode=value.get('block_cipher_mode'),
            padding_method=value.get('padding_method'),
            hashing_algorithm=value.get('hashing_algorithm'),
            key_role_type=value.get('key_role_type'),
            digital_signature_algorithm=value.get(
                'digital_signature_algorithm'
            ),
            cryptographic_algorithm=value.get('cryptographic_algorithm'),
            random_iv=value.get('random_iv'),
            iv_length=value.get('iv_length'),
            tag_length=value.get('tag_length'),
            fixed_field_length=value.get('fixed_field_length'),
            invocation_field_length=value.get('invocation_field_length'),
            counter_length=value.get('counter_length'),
            initial_counter_value=value.get('initial_counter_value')
        )
        return cryptographic_parameters

    def _build_encryption_key_information(self, value):
        """
        Build an EncryptionKeyInformation struct from a dictionary.

        Args:
            value (dict): A dictionary containing the key/value pairs for a
                EncryptionKeyInformation struct.

        Returns:
            EncryptionKeyInformation: an EncryptionKeyInformation struct

        Raises:
            TypeError: if the input argument is invalid
        """
        if value is None:
            return None
        if not isinstance(value, dict):
            raise TypeError("Encryption key information must be a dictionary.")

        cryptographic_parameters = value.get('cryptographic_parameters')
        if cryptographic_parameters:
            cryptographic_parameters = self._build_cryptographic_parameters(
                cryptographic_parameters
            )
        encryption_key_information = cobjects.EncryptionKeyInformation(
            unique_identifier=value.get('unique_identifier'),
            cryptographic_parameters=cryptographic_parameters
        )
        return encryption_key_information

    def _build_mac_signature_key_information(self, value):
        """
        Build an MACSignatureKeyInformation struct from a dictionary.

        Args:
            value (dict): A dictionary containing the key/value pairs for a
                MACSignatureKeyInformation struct.

        Returns:
            MACSignatureInformation: a MACSignatureKeyInformation struct

        Raises:
            TypeError: if the input argument is invalid
        """
        if value is None:
            return None
        if not isinstance(value, dict):
            raise TypeError(
                "MAC/signature key information must be a dictionary."
            )

        cryptographic_parameters = value.get('cryptographic_parameters')
        if cryptographic_parameters:
            cryptographic_parameters = self._build_cryptographic_parameters(
                cryptographic_parameters
            )
        mac_signature_key_information = cobjects.MACSignatureKeyInformation(
            unique_identifier=value.get('unique_identifier'),
            cryptographic_parameters=cryptographic_parameters
        )
        return mac_signature_key_information

    def _build_key_wrapping_specification(self, value):
        """
        Build a KeyWrappingSpecification struct from a dictionary.

        Args:
            value (dict): A dictionary containing the key/value pairs for a
                KeyWrappingSpecification struct.

        Returns:
            KeyWrappingSpecification: a KeyWrappingSpecification struct

        Raises:
            TypeError: if the input argument is invalid
        """
        if value is None:
            return None
        if not isinstance(value, dict):
            raise TypeError("Key wrapping specification must be a dictionary.")

        encryption_key_info = self._build_encryption_key_information(
            value.get('encryption_key_information')
        )
        mac_signature_key_info = self._build_mac_signature_key_information(
            value.get('mac_signature_key_information')
        )

        key_wrapping_specification = cobjects.KeyWrappingSpecification(
            wrapping_method=value.get('wrapping_method'),
            encryption_key_information=encryption_key_info,
            mac_signature_key_information=mac_signature_key_info,
            attribute_names=value.get('attribute_names'),
            encoding_option=value.get('encoding_option')
        )
        return key_wrapping_specification

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

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
