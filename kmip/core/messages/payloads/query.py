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

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import misc
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class QueryRequestPayload(base.RequestPayload):
    """
    A request payload for the Query operation.

    The payload contains a list of query functions that the KMIP server should
    respond to. See Section 4.25 of the KMIP 1.1 specification for more
    information.

    Attributes:
        query_functions: A list of QueryFunction enumerations.
    """
    def __init__(self, query_functions=None):
        """
        Construct a QueryRequestPayload object.

        Args:
            query_functions (list): A list of QueryFunction enumerations.
        """
        super(QueryRequestPayload, self).__init__()

        self._query_functions = None

        self.query_functions = query_functions

    @property
    def query_functions(self):
        if self._query_functions:
            return [x.value for x in self._query_functions]
        return None

    @query_functions.setter
    def query_functions(self, value):
        if value is None:
            self._query_functions = None
        elif isinstance(value, list):
            query_functions = []
            for v in value:
                if isinstance(v, enums.QueryFunction):
                    query_functions.append(
                        primitives.Enumeration(
                            enums.QueryFunction,
                            value=v,
                            tag=enums.Tags.QUERY_FUNCTION
                        )
                    )
                else:
                    raise TypeError(
                        "The query functions must be a list of QueryFunction "
                        "enumerations."
                    )
            self._query_functions = query_functions
        else:
            raise TypeError(
                "The query functions must be a list of QueryFunction "
                "enumerations."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the QueryRequestPayload object and decode it
        into its constituent parts.

        Args:
            input_buffer (Stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidKmipEncoding: Raised if the query functions are missing
                from the encoded payload.
        """
        super(QueryRequestPayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        query_functions = []
        while (self.is_tag_next(enums.Tags.QUERY_FUNCTION, local_buffer)):
            query_function = primitives.Enumeration(
                enums.QueryFunction,
                tag=enums.Tags.QUERY_FUNCTION
            )
            query_function.read(local_buffer, kmip_version=kmip_version)
            query_functions.append(query_function)

        if query_functions:
            self._query_functions = query_functions
        else:
            raise exceptions.InvalidKmipEncoding(
                "The Query request payload encoding is missing the query "
                "functions."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the QueryRequestPayload object to a stream.

        Args:
            output_buffer (Stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            InvalidField: Raised if the query functions are not defined.
        """
        local_buffer = utils.BytearrayStream()

        if self._query_functions:
            for query_function in self._query_functions:
                query_function.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The Query request payload is missing the query functions "
                "field."
            )

        self.length = local_buffer.length()
        super(QueryRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        d = "query_functions={}".format(
            "[{}]".format(
                ", ".join(["{}".format(x) for x in self.query_functions])
            ) if self.query_functions else None
        )
        return "QueryRequestPayload({})".format(d)

    def __str__(self):
        d = '"query_functions": {}'.format(
            "[{}]".format(
                ", ".join(["{}".format(x) for x in self.query_functions])
            ) if self.query_functions else None
        )
        return "{" + d + "}"

    def __eq__(self, other):
        if isinstance(other, QueryRequestPayload):
            if self.query_functions == other.query_functions:
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, QueryRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

class QueryResponsePayload(base.ResponsePayload):
    """
    A response payload for the Query operation.

    The payload contains different sets of responses that the KMIP server
    provides in response to the initial Query request.

    Attributes:
        operations: A list of Operations supported by the server.
        object_types: A list of ObjectTypes supported by the server.
        vendor_identification: A string identifying the server vendor.
        server_information: A structure containing vendor-specific fields and
            substructures.
        application_namespaces: A list of application namespaces supported by
            the server.
        extension_information: A list of ExtensionInformation objects
            detailing Objects supported by the server with ItemTag values in
            the Extensions range. Added in KMIP 1.1.
        attestation_types: A list of AttestationType enumerations detailing
            the attestation methods supported by the server. Added in KMIP 1.2.
        rng_parameters: A list of RNGParameters structures detailing the types
            of random number generators supported by the server. Added in
            KMIP 1.3.
        profile_information: A list of ProfileInformation structures detailing
            the different profiles supported by the server. Added in KMIP 1.3.
        validation_information: A list of ValidationInformation structures
            detailing the types of formal validation supported by the server.
            Added in KMIP 1.3.
        capability_information: A list of CapabilityInformation structures
            detailing the different capabilities supported by the server.
            Added in KMIP 1.3.
        client_registration_methods: A list of ClientRegistrationMethod
            enumerations detailing the different client registration methods
            supported by the server. Added in KMIP 1.3.
        defaults_information: A DefaultsInformation structure detailing the
            default attribute values used by the server for new managed
            objects. Added in KMIP 2.0.
        protection__storage_mask: A list of integers representing combined sets
            of ProtectionStorageMask enumerations detailing the storage
            protections supported by the server. Added in KMIP 2.0.
    """
    def __init__(self,
                 operations=None,
                 object_types=None,
                 vendor_identification=None,
                 server_information=None,
                 application_namespaces=None,
                 extension_information=None,
                 attestation_types=None,
                 rng_parameters=None,
                 profile_information=None,
                 validation_information=None,
                 capability_information=None,
                 client_registration_methods=None,
                 defaults_information=None,
                 protection_storage_masks=None):
        """
        Construct a QueryResponsePayload object.

        Args:
            operations (list): A list of Operations supported by the server.
                Optional, defaults to None.
            object_types (list): A list of ObjectTypes supported by the
                server. Optional, defaults to None.
            vendor_identification (string): A string identifying the server
                vendor. Optional, defaults to None.
            server_information (structure): A ServerInformation structure
                containing vendor-specific fields and substructures. Optional,
                defaults to None.
            application_namespaces (list): A list of application namespaces
                supported by the server. Optional, defaults to None.
            extension_information (list): A list of ExtensionInformation
                objects detailing Objects supported by the server with ItemTag
                values in the Extensions range. Optional, defaults to None.
                Added in KMIP 1.1.
            attestation_types (list): A list of AttestationType enumerations
                detailing the attestation methods supported by the server.
                Optional, defaults to None. Added in KMIP 1.2.
            rng_parameters (list): A list of RNGParameters structures detailing
                the types of random number generators supported by the server.
                Optional, defaults to None. Added in KMIP 1.3.
            profile_information (list): A list of ProfileInformation structures
                detailing the different profiles supported by the server.
                Optional, defaults to None. Added in KMIP 1.3.
            validation_information (list): A list of ValidationInformation
                structures detailing the types of formal validation supported
                by the server. Optional, defaults to None. Added in KMIP 1.3.
            capability_information (list): A list of CapabilityInformation
                structures detailing the different capabilities supported by
                the server. Optional, defaults to None. Added in KMIP 1.3.
            client_registration_methods (list): A list of
                ClientRegistrationMethod enumerations detailing the different
                client registration methods supported by the server. Optional,
                defaults to None. Added in KMIP 1.3.
            defaults_information (structure): A DefaultsInformation structure
                detailing the default attribute values used by the server for
                new managed objects. Optional, defaults to None. Added in
                KMIP 2.0.
            protection__storage_masks (list): A list of integers representing
                combined sets of ProtectionStorageMask enumerations detailing
                the storage protections supported by the server. Optional,
                defaults to None. Added in KMIP 2.0.
        """
        super(QueryResponsePayload, self).__init__()
        self._operations = None
        self._object_types = None
        self._vendor_identification = None
        self._server_information = None
        self._application_namespaces = None
        self._extension_information = None
        self._attestation_types = None
        self._rng_parameters = None
        self._profile_information = None
        self._validation_information = None
        self._capability_information = None
        self._client_registration_methods = None
        self._defaults_information = None
        self._storage_protection_masks = None

        self.operations = operations
        self.object_types = object_types
        self.vendor_identification = vendor_identification
        self.server_information = server_information
        self.application_namespaces = application_namespaces
        self.extension_information = extension_information
        self.attestation_types = attestation_types
        self.rng_parameters = rng_parameters
        self.profile_information = profile_information
        self.validation_information = validation_information
        self.capability_information = capability_information
        self.client_registration_methods = client_registration_methods
        self.defaults_information = defaults_information
        self.protection_storage_masks = protection_storage_masks

    @property
    def operations(self):
        if self._operations:
            return [x.value for x in self._operations]
        return None

    @operations.setter
    def operations(self, value):
        if value is None:
            self._operations = None
        elif isinstance(value, list):
            operations = []
            for i in value:
                if isinstance(i, enums.Operation):
                    operations.append(
                        primitives.Enumeration(
                            enums.Operation,
                            value=i,
                            tag=enums.Tags.OPERATION
                        )
                    )
                else:
                    raise TypeError(
                        "The operations must be a list of Operation "
                        "enumerations."
                    )
            self._operations = operations
        else:
            raise TypeError(
                "The operations must be a list of Operation enumerations."
            )

    @property
    def object_types(self):
        if self._object_types:
            return [x.value for x in self._object_types]
        return None

    @object_types.setter
    def object_types(self, value):
        if value is None:
            self._object_types = None
        elif isinstance(value, list):
            object_types = []
            for i in value:
                if isinstance(i, enums.ObjectType):
                    object_types.append(
                        primitives.Enumeration(
                            enums.ObjectType,
                            value=i,
                            tag=enums.Tags.OBJECT_TYPE
                        )
                    )
                else:
                    raise TypeError(
                        "The object types must be a list of ObjectType "
                        "enumerations."
                    )
            self._object_types = object_types
        else:
            raise TypeError(
                "The object types must be a list of ObjectType enumerations."
            )

    @property
    def vendor_identification(self):
        if self._vendor_identification:
            return self._vendor_identification.value
        return None

    @vendor_identification.setter
    def vendor_identification(self, value):
        if value is None:
            self._vendor_identification = None
        elif isinstance(value, str):
            self._vendor_identification = primitives.TextString(
                value=value,
                tag=enums.Tags.VENDOR_IDENTIFICATION
            )
        else:
            raise TypeError("The vendor identification must be a string.")

    @property
    def server_information(self):
        return self._server_information

    @server_information.setter
    def server_information(self, value):
        if value is None:
            self._server_information = None
        elif isinstance(value, misc.ServerInformation):
            self._server_information = value
        else:
            raise TypeError(
                "The server information must be a ServerInformation structure."
            )

    @property
    def application_namespaces(self):
        if self._application_namespaces:
            return [x.value for x in self._application_namespaces]
        return None

    @application_namespaces.setter
    def application_namespaces(self, value):
        if value is None:
            self._application_namespaces = None
        elif isinstance(value, list):
            application_namespaces = []
            for i in value:
                if isinstance(i, str):
                    application_namespaces.append(
                        primitives.TextString(
                            value=i,
                            tag=enums.Tags.APPLICATION_NAMESPACE
                        )
                    )
                else:
                    raise TypeError(
                        "The application namespaces must be a list of strings."
                    )
            self._application_namespaces = application_namespaces
        else:
            raise TypeError(
                "The application namespaces must be a list of strings."
            )

    @property
    def extension_information(self):
        if self._extension_information:
            return [x for x in self._extension_information]
        return None

    @extension_information.setter
    def extension_information(self, value):
        if value is None:
            self._extension_information = None
        elif isinstance(value, list):
            extension_information = []
            for i in value:
                if isinstance(i, objects.ExtensionInformation):
                    extension_information.append(i)
                else:
                    raise TypeError(
                        "The extension information must be a list of "
                        "ExtensionInformation structures."
                    )
            self._extension_information = extension_information
        else:
            raise TypeError(
                "The extension information must be a list of "
                "ExtensionInformation structures."
            )

    @property
    def attestation_types(self):
        if self._attestation_types:
            return [x.value for x in self._attestation_types]
        return None

    @attestation_types.setter
    def attestation_types(self, value):
        if value is None:
            self._attestation_types = None
        elif isinstance(value, list):
            attestation_types = []
            for i in value:
                if isinstance(i, enums.AttestationType):
                    attestation_types.append(
                        primitives.Enumeration(
                            enums.AttestationType,
                            value=i,
                            tag=enums.Tags.ATTESTATION_TYPE
                        )
                    )
                else:
                    raise TypeError(
                        "The attestation types must be a list of "
                        "AttestationType enumerations."
                    )
            self._attestation_types = attestation_types
        else:
            raise TypeError(
                "The attestation types must be a list of AttestationType "
                "enumerations."
            )

    @property
    def rng_parameters(self):
        return self._rng_parameters

    @rng_parameters.setter
    def rng_parameters(self, value):
        if value is None:
            self._rng_parameters = None
        elif isinstance(value, list):
            rng_parameters = []
            for i in value:
                if isinstance(i, objects.RNGParameters):
                    rng_parameters.append(i)
                else:
                    raise TypeError(
                        "The RNG parameters must be a list of RNGParameters "
                        "structures."
                    )
            self._rng_parameters = rng_parameters
        else:
            raise TypeError(
                "The RNG parameters must be a list of RNGParameters "
                "structures."
            )

    @property
    def profile_information(self):
        return self._profile_information

    @profile_information.setter
    def profile_information(self, value):
        if value is None:
            self._profile_information = None
        elif isinstance(value, list):
            profile_information = []
            for i in value:
                if isinstance(i, objects.ProfileInformation):
                    profile_information.append(i)
                else:
                    raise TypeError(
                        "The profile information must be a list of "
                        "ProfileInformation structures."
                    )
            self._profile_information = profile_information
        else:
            raise TypeError(
                "The profile information must be a list of "
                "ProfileInformation structures."
            )

    @property
    def validation_information(self):
        return self._validation_information

    @validation_information.setter
    def validation_information(self, value):
        if value is None:
            self._validation_information = None
        elif isinstance(value, list):
            validation_information = []
            for i in value:
                if isinstance(i, objects.ValidationInformation):
                    validation_information.append(i)
                else:
                    raise TypeError(
                        "The validation information must be a list of "
                        "ValidationInformation structures."
                    )
            self._validation_information = validation_information
        else:
            raise TypeError(
                "The validation information must be a list of "
                "ValidationInformation structures."
            )

    @property
    def capability_information(self):
        return self._capability_information

    @capability_information.setter
    def capability_information(self, value):
        if value is None:
            self._capability_information = None
        elif isinstance(value, list):
            capability_information = []
            for i in value:
                if isinstance(i, objects.CapabilityInformation):
                    capability_information.append(i)
                else:
                    raise TypeError(
                        "The capability information must be a list of "
                        "CapabilityInformation structures."
                    )
            self._capability_information = capability_information
        else:
            raise TypeError(
                "The capability information must be a list of "
                "CapabilityInformation structures."
            )

    @property
    def client_registration_methods(self):
        if self._client_registration_methods:
            return [x.value for x in self._client_registration_methods]
        return None

    @client_registration_methods.setter
    def client_registration_methods(self, value):
        if value is None:
            self._client_registration_methods = None
        elif isinstance(value, list):
            client_registration_methods = []
            for i in value:
                if isinstance(i, enums.ClientRegistrationMethod):
                    client_registration_methods.append(
                        primitives.Enumeration(
                            enums.ClientRegistrationMethod,
                            value=i,
                            tag=enums.Tags.CLIENT_REGISTRATION_METHOD
                        )
                    )
                else:
                    raise TypeError(
                        "The client registration methods must be a list of "
                        "ClientRegistrationMethod enumerations."
                    )
            self._client_registration_methods = client_registration_methods
        else:
            raise TypeError(
                "The client registration methods must be a list of "
                "ClientRegistrationMethod enumerations."
            )

    @property
    def defaults_information(self):
        return self._defaults_information

    @defaults_information.setter
    def defaults_information(self, value):
        if value is None:
            self._defaults_information = None
        elif isinstance(value, objects.DefaultsInformation):
            self._defaults_information = value
        else:
            raise TypeError(
                "The defaults information must be a DefaultsInformation "
                "structure."
            )

    @property
    def protection_storage_masks(self):
        if self._protection_storage_masks:
            return [x.value for x in self._protection_storage_masks]
        return None

    @protection_storage_masks.setter
    def protection_storage_masks(self, value):
        if value is None:
            self._protection_storage_masks = None
        elif isinstance(value, list):
            protection_storage_masks = []
            for i in value:
                if isinstance(i, int):
                    protection_storage_masks.append(
                        primitives.Integer(
                            value=i,
                            tag=enums.Tags.PROTECTION_STORAGE_MASK
                        )
                    )
                else:
                    raise TypeError(
                        "The protection storage masks must be a list of "
                        "integers."
                    )
            self._protection_storage_masks = protection_storage_masks
        else:
            raise TypeError(
                "The protection storage masks must be a list of integers."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the QueryResponsePayload object and decode it
        into its constituent parts.

        Args:
            input_buffer (Stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(QueryResponsePayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        operations = []
        while (self.is_tag_next(enums.Tags.OPERATION, local_buffer)):
            operation = primitives.Enumeration(
                enums.Operation,
                tag=enums.Tags.OPERATION
            )
            operation.read(local_buffer, kmip_version=kmip_version)
            operations.append(operation)
        self._operations = operations

        object_types = []
        while (self.is_tag_next(enums.Tags.OBJECT_TYPE, local_buffer)):
            object_type = primitives.Enumeration(
                enums.ObjectType,
                tag=enums.Tags.OBJECT_TYPE
            )
            object_type.read(local_buffer, kmip_version=kmip_version)
            object_types.append(object_type)
        self._object_types = object_types

        if self.is_tag_next(enums.Tags.VENDOR_IDENTIFICATION, local_buffer):
            vendor_identification = primitives.TextString(
                tag=enums.Tags.VENDOR_IDENTIFICATION
            )
            vendor_identification.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._vendor_identification = vendor_identification

        if self.is_tag_next(enums.Tags.SERVER_INFORMATION, local_buffer):
            server_information = misc.ServerInformation()
            server_information.read(
                local_buffer,
                kmip_version=kmip_version
            )
            self._server_information = server_information

        application_namespaces = []
        while (self.is_tag_next(
                enums.Tags.APPLICATION_NAMESPACE,
                local_buffer
            )
        ):
            application_namespace = primitives.TextString(
                tag=enums.Tags.APPLICATION_NAMESPACE
            )
            application_namespace.read(local_buffer, kmip_version=kmip_version)
            application_namespaces.append(application_namespace)
        self._application_namespaces = application_namespaces

        if kmip_version >= enums.KMIPVersion.KMIP_1_1:
            extensions_information = []
            while (self.is_tag_next(
                    enums.Tags.EXTENSION_INFORMATION,
                    local_buffer
                )
            ):
                extension_information = objects.ExtensionInformation()
                extension_information.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                extensions_information.append(extension_information)
            self._extension_information = extensions_information

        if kmip_version >= enums.KMIPVersion.KMIP_1_2:
            attestation_types = []
            while (self.is_tag_next(
                    enums.Tags.ATTESTATION_TYPE,
                    local_buffer
                )
            ):
                attestation_type = primitives.Enumeration(
                    enums.AttestationType,
                    tag=enums.Tags.ATTESTATION_TYPE
                )
                attestation_type.read(local_buffer, kmip_version=kmip_version)
                attestation_types.append(attestation_type)
            self._attestation_types = attestation_types

        if kmip_version >= enums.KMIPVersion.KMIP_1_3:
            rngs_parameters = []
            while (self.is_tag_next(enums.Tags.RNG_PARAMETERS, local_buffer)):
                rng_parameters = objects.RNGParameters()
                rng_parameters.read(local_buffer, kmip_version=kmip_version)
                rngs_parameters.append(rng_parameters)
            self._rng_parameters = rngs_parameters

            profiles_information = []
            while (self.is_tag_next(
                    enums.Tags.PROFILE_INFORMATION,
                    local_buffer
                )
            ):
                profile_information = objects.ProfileInformation()
                profile_information.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                profiles_information.append(profile_information)
            self._profile_information = profiles_information

            validations_information = []
            while (self.is_tag_next(
                    enums.Tags.VALIDATION_INFORMATION,
                    local_buffer
                )
            ):
                validation_information = objects.ValidationInformation()
                validation_information.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                validations_information.append(validation_information)
            self._validation_information = validations_information

            capabilities_information = []
            while (self.is_tag_next(
                    enums.Tags.CAPABILITY_INFORMATION,
                    local_buffer
                )
            ):
                capability_information = objects.CapabilityInformation()
                capability_information.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                capabilities_information.append(capability_information)
            self._capability_information = capabilities_information

            client_registration_methods = []
            while (self.is_tag_next(
                    enums.Tags.CLIENT_REGISTRATION_METHOD,
                    local_buffer
                )
            ):
                client_registration_method = primitives.Enumeration(
                    enums.ClientRegistrationMethod,
                    tag=enums.Tags.CLIENT_REGISTRATION_METHOD
                )
                client_registration_method.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                client_registration_methods.append(client_registration_method)
            self._client_registration_methods = client_registration_methods

        if kmip_version >= enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(enums.Tags.DEFAULTS_INFORMATION, local_buffer):
                defaults_information = objects.DefaultsInformation()
                defaults_information.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                self._defaults_information = defaults_information

            protection_storage_masks = []
            while (self.is_tag_next(
                    enums.Tags.PROTECTION_STORAGE_MASK,
                    local_buffer
                )
            ):
                protection_storage_mask = primitives.Integer(
                    tag=enums.Tags.PROTECTION_STORAGE_MASK
                )
                protection_storage_mask.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
                protection_storage_masks.append(protection_storage_mask)
            self._protection_storage_masks = protection_storage_masks

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the QueryResponsePayload object to a stream.

        Args:
            output_buffer (Stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_buffer = utils.BytearrayStream()

        if self._operations:
            for operation in self._operations:
                operation.write(local_buffer, kmip_version=kmip_version)

        if self._object_types:
            for object_type in self._object_types:
                object_type.write(local_buffer, kmip_version=kmip_version)

        if self._vendor_identification:
            self._vendor_identification.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._server_information:
            self._server_information.write(
                local_buffer,
                kmip_version=kmip_version
            )

        if self._application_namespaces:
            for application_namespace in self._application_namespaces:
                application_namespace.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        if kmip_version >= enums.KMIPVersion.KMIP_1_1:
            if self._extension_information:
                for extension_information in self._extension_information:
                    extension_information.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )

        if kmip_version >= enums.KMIPVersion.KMIP_1_2:
            if self._attestation_types:
                for attestation_type in self._attestation_types:
                    attestation_type.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )

        if kmip_version >= enums.KMIPVersion.KMIP_1_3:
            if self._rng_parameters:
                for rng_parameters in self._rng_parameters:
                    rng_parameters.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )
            if self._profile_information:
                for profile_information in self._profile_information:
                    profile_information.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )
            if self._validation_information:
                for validation_information in self._validation_information:
                    validation_information.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )
            if self._capability_information:
                for capability_information in self._capability_information:
                    capability_information.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )
            if self._client_registration_methods:
                for client_reg_method in self._client_registration_methods:
                    client_reg_method.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )

        if kmip_version >= enums.KMIPVersion.KMIP_2_0:
            if self._defaults_information:
                self._defaults_information.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            if self._protection_storage_masks:
                for protection_storage_mask in self._protection_storage_masks:
                    protection_storage_mask.write(
                        local_buffer,
                        kmip_version=kmip_version
                    )

        self.length = local_buffer.length()
        super(QueryResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        o = "operations={}".format(
            "[{}]".format(
                ", ".join([str(x) for x in self.operations])
            ) if self.operations else None
        )
        ot = "object_types={}".format(
            "[{}]".format(
                ", ".join([str(x) for x in self.object_types])
            ) if self.object_types else None
        )
        vi = 'vendor_identification="{}"'.format(self.vendor_identification)
        si = "server_information={}".format(repr(self.server_information))
        an = "application_namespaces={}".format(
            "[{}]".format(
                ", ".join(
                    ['"{}"'.format(x) for x in self.application_namespaces]
                )
            ) if self.application_namespaces else None
        )
        ei = "extension_information={}".format(
            "[{}]".format(
                ", ".join([repr(x) for x in self.extension_information])
            ) if self.extension_information else None
        )
        at = "attestation_types={}".format(
            "[{}]".format(
                ", ".join([str(x) for x in self.attestation_types])
            ) if self.attestation_types else None
        )
        rp = "rng_parameters={}".format(
            "[{}]".format(
                ", ".join([repr(x) for x in self.rng_parameters])
            ) if self.rng_parameters else None
        )
        pi = "profile_information={}".format(
            "[{}]".format(
                ", ".join([repr(x) for x in self.profile_information])
            ) if self.profile_information else None
        )
        vai = "validation_information={}".format(
            "[{}]".format(
                ", ".join([repr(x) for x in self.validation_information])
            ) if self.validation_information else None
        )
        ci = "capability_information={}".format(
            "[{}]".format(
                ", ".join([repr(x) for x in self.capability_information])
            ) if self.capability_information else None
        )
        crm = "client_registration_methods={}".format(
            "[{}]".format(
                ", ".join([str(x) for x in self.client_registration_methods])
            ) if self.client_registration_methods else None
        )
        di = "defaults_information={}".format(
            "{}".format(
                repr(self._defaults_information)
            ) if self._defaults_information else None
        )
        spm = "protection_storage_masks={}".format(
            "[{}]".format(
                ", ".join([str(x) for x in self.protection_storage_masks])
            ) if self._protection_storage_masks else None
        )

        v = ", ".join(
            [o, ot, vi, si, an, ei, at, rp, pi, vai, ci, crm, di, spm]
        )

        return "QueryResponsePayload({})".format(v)

    def __str__(self):
        o = '"operations": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.operations])
            ) if self.operations else None
        )
        ot = '"object_types": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.object_types])
            ) if self.object_types else None
        )
        vi = '"vendor_identification": "{}"'.format(self.vendor_identification)
        si = '"server_information": {}'.format(repr(self.server_information))
        an = '"application_namespaces": {}'.format(
            "[{}]".format(
                ", ".join(
                    ['"{}"'.format(x) for x in self.application_namespaces]
                )
            ) if self.application_namespaces else None
        )
        ei = '"extension_information": {}'.format(
            "[{}]".format(
                ", ".join([repr(x) for x in self.extension_information])
            ) if self.extension_information else None
        )
        at = '"attestation_types": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.attestation_types])
            ) if self.attestation_types else None
        )
        rp = '"rng_parameters": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.rng_parameters])
            ) if self.rng_parameters else None
        )
        pi = '"profile_information": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.profile_information])
            ) if self.profile_information else None
        )
        vai = '"validation_information": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.validation_information])
            ) if self.validation_information else None
        )
        ci = '"capability_information": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.capability_information])
            ) if self.capability_information else None
        )
        crm = '"client_registration_methods": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.client_registration_methods])
            ) if self.client_registration_methods else None
        )
        di = '"defaults_information": {}'.format(
            "{}".format(
                str(self.defaults_information)
            ) if self._defaults_information else None
        )
        spm = '"protection_storage_masks": {}'.format(
            "[{}]".format(
                ", ".join([str(x) for x in self.protection_storage_masks])
            ) if self._protection_storage_masks else None
        )

        v = ", ".join(
            [o, ot, vi, si, an, ei, at, rp, pi, vai, ci, crm, di, spm]
        )

        return '{' + v + '}'

    def __eq__(self, other):
        if isinstance(other, QueryResponsePayload):
            if self.operations != other.operations:
                return False
            elif self.object_types != other.object_types:
                return False
            elif self.vendor_identification != other.vendor_identification:
                return False
            elif self.server_information != other.server_information:
                return False
            elif self.application_namespaces != other.application_namespaces:
                return False
            elif self.extension_information != other.extension_information:
                return False
            elif self.attestation_types != other.attestation_types:
                return False
            elif self.rng_parameters != other.rng_parameters:
                return False
            elif self.profile_information != other.profile_information:
                return False
            elif self.validation_information != other.validation_information:
                return False
            elif self.capability_information != other.capability_information:
                return False
            elif self.client_registration_methods != \
                    other.client_registration_methods:
                return False
            elif self.defaults_information != other.defaults_information:
                return False
            elif self.protection_storage_masks != \
                    other.protection_storage_masks:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, QueryResponsePayload):
            return not (self == other)
        else:
            return NotImplemented
