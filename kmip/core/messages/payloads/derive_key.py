# Copyright (c) 2017 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class DeriveKeyRequestPayload(base.RequestPayload):
    """
    A request payload for the DeriveKey operation.

    Attributes:
        object_type: The type of the object that should be derived.
        unique_identifiers: A set of unique IDs of managed objects to be used
            with the derivation process.
        derivation_method: The method that should be used to derive the new
            cryptographic object.
        derivation_parameters: A collection of settings relevant for the
            derivation method.
        template_attribute: A collection of attributes that should be set on
            the newly derived cryptographic object.
    """

    def __init__(self,
                 object_type=None,
                 unique_identifiers=None,
                 derivation_method=None,
                 derivation_parameters=None,
                 template_attribute=None):
        """
        Construct a DeriveKey request payload struct.

        Args:
            object_type (enum): An ObjectType enumeration specifying the type
                of the object to derive. Optional, defaults to None. Required
                for read/write.
            unique_identifiers (list): A list of strings representing the IDs
                of managed objects (e.g., symmetric keys) to be used for
                derivation. Optional, defaults to None. At least one value is
                required for read/write.
            derivation_method (enum): A DerivationMethod enumeration
                specifying the type of derivation function to use (e.g.,
                PBKDF2). Optional, defaults to None. Required for read/write.
            derivation_parameters (DerivationParameters): A structure
                containing cryptographic settings relevant for the derivation
                method. Optional, defaults to None. Required for read/write.
            template_attribute (TemplateAttribute): A structure containing a
                set of attributes (e.g., cryptographic algorithm,
                cryptographic length) that should be set on the newly derived
                cryptographic object. Optional, defaults to None. Required
                for read/write.
        """
        super(DeriveKeyRequestPayload, self).__init__()

        self._object_type = None
        self._unique_identifiers = None
        self._derivation_method = None
        self._derivation_parameters = None
        self._template_attribute = None

        self.object_type = object_type
        self.unique_identifiers = unique_identifiers
        self.derivation_method = derivation_method
        self.derivation_parameters = derivation_parameters
        self.template_attribute = template_attribute

    @property
    def object_type(self):
        if self._object_type:
            return self._object_type.value
        else:
            return None

    @object_type.setter
    def object_type(self, value):
        if value is None:
            self._object_type = None
        elif isinstance(value, enums.ObjectType):
            self._object_type = primitives.Enumeration(
                enums.ObjectType,
                value=value,
                tag=enums.Tags.OBJECT_TYPE
            )
        else:
            raise TypeError("Object type must be an ObjectType enumeration.")

    @property
    def unique_identifiers(self):
        if self._unique_identifiers:
            unique_identifiers = []
            for i in self._unique_identifiers:
                unique_identifiers.append(i.value)
            return unique_identifiers
        else:
            return None

    @unique_identifiers.setter
    def unique_identifiers(self, value):
        if value is None:
            self._unique_identifiers = None
        elif isinstance(value, list):
            unique_identifiers = []
            for i in value:
                if isinstance(i, str):
                    unique_identifiers.append(
                        primitives.TextString(
                            value=i,
                            tag=enums.Tags.UNIQUE_IDENTIFIER
                        )
                    )
                else:
                    raise TypeError(
                        "Unique identifiers must be a list of strings."
                    )
            self._unique_identifiers = unique_identifiers
        else:
            raise TypeError("Unique identifiers must be a list of strings.")

    @property
    def derivation_method(self):
        if self._derivation_method:
            return self._derivation_method.value
        else:
            return None

    @derivation_method.setter
    def derivation_method(self, value):
        if value is None:
            self._derivation_method = None
        elif isinstance(value, enums.DerivationMethod):
            self._derivation_method = primitives.Enumeration(
                enums.DerivationMethod,
                value=value,
                tag=enums.Tags.DERIVATION_METHOD
            )
        else:
            raise TypeError(
                "Derivation method must be a DerivationMethod enumeration."
            )

    @property
    def derivation_parameters(self):
        if self._derivation_parameters:
            return self._derivation_parameters
        else:
            return None

    @derivation_parameters.setter
    def derivation_parameters(self, value):
        if value is None:
            self._derivation_parameters = None
        elif isinstance(value, attributes.DerivationParameters):
            self._derivation_parameters = value
        else:
            raise TypeError(
                "Derivation parameters must be a DerivationParameters "
                "structure."
            )

    @property
    def template_attribute(self):
        if self._template_attribute:
            return self._template_attribute
        else:
            return None

    @template_attribute.setter
    def template_attribute(self, value):
        if value is None:
            self._template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            self._template_attribute = value
        else:
            raise TypeError(
                "Template attribute must be a TemplateAttribute structure."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the DeriveKey request payload and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(DeriveKeyRequestPayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.OBJECT_TYPE, local_buffer):
            self._object_type = primitives.Enumeration(
                enums.ObjectType,
                tag=enums.Tags.OBJECT_TYPE
            )
            self._object_type.read(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidKmipEncoding(
                "The DeriveKey request payload encoding is missing the object "
                "type."
            )

        unique_identifiers = []
        while self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_buffer):
            unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            unique_identifier.read(local_buffer, kmip_version=kmip_version)
            unique_identifiers.append(unique_identifier)
        if not unique_identifiers:
            raise exceptions.InvalidKmipEncoding(
                "The DeriveKey request payload encoding is missing the unique "
                "identifiers."
            )
        else:
            self._unique_identifiers = unique_identifiers

        if self.is_tag_next(enums.Tags.DERIVATION_METHOD, local_buffer):
            self._derivation_method = primitives.Enumeration(
                enums.DerivationMethod,
                tag=enums.Tags.DERIVATION_METHOD
            )
            self._derivation_method.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The DeriveKey request payload encoding is missing the "
                "derivation method."
            )

        if self.is_tag_next(enums.Tags.DERIVATION_PARAMETERS, local_buffer):
            self._derivation_parameters = attributes.DerivationParameters()
            self._derivation_parameters.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The DeriveKey request payload encoding is missing the "
                "derivation parameters."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_buffer):
                self._template_attribute = objects.TemplateAttribute()
                self._template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                raise exceptions.InvalidKmipEncoding(
                    "The DeriveKey request payload encoding is missing the "
                    "template attribute."
                )
        else:
            if self.is_tag_next(enums.Tags.ATTRIBUTES, local_buffer):
                attrs = objects.Attributes()
                attrs.read(local_buffer, kmip_version=kmip_version)
                value = objects.convert_attributes_to_template_attribute(
                    attrs
                )
                self._template_attribute = value
            else:
                raise exceptions.InvalidKmipEncoding(
                    "The DeriveKey request payload encoding is missing the "
                    "attributes structure."
                )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the DeriveKey request payload to a stream.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_buffer = utils.BytearrayStream()

        if self._object_type:
            self._object_type.write(local_buffer, kmip_version=kmip_version)
        else:
            raise exceptions.InvalidField(
                "The DeriveKey request payload is missing the object type "
                "field."
            )

        if self._unique_identifiers:
            for unique_identifier in self._unique_identifiers:
                unique_identifier.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
        else:
            raise exceptions.InvalidField(
                "The DeriveKey request payload is missing the unique "
                "identifiers field."
            )

        if self._derivation_method:
            self._derivation_method.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The DeriveKey request payload is missing the derivation "
                "method field."
            )

        if self._derivation_parameters:
            self._derivation_parameters.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The DeriveKey request payload is missing the derivation "
                "parameters field."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._template_attribute:
                self._template_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )
            else:
                raise exceptions.InvalidField(
                    "The DeriveKey request payload is missing the template "
                    "attribute field."
                )
        else:
            if self._template_attribute:
                attrs = objects.convert_template_attribute_to_attributes(
                    self._template_attribute
                )
                attrs.write(local_buffer, kmip_version=kmip_version)
            else:
                raise exceptions.InvalidField(
                    "The DeriveKey request payload is missing the template "
                    "attribute field."
                )

        self.length = local_buffer.length()
        super(DeriveKeyRequestPayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, DeriveKeyRequestPayload):
            if self.object_type != other.object_type:
                return False
            elif self.unique_identifiers != other.unique_identifiers:
                return False
            elif self.derivation_method != other.derivation_method:
                return False
            elif self.derivation_parameters != other.derivation_parameters:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DeriveKeyRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "object_type={0}".format(self.object_type),
            "unique_identifiers={0}".format(self.unique_identifiers),
            "derivation_method={0}".format(self.derivation_method),
            "derivation_parameters={0}".format(
                repr(self.derivation_parameters)
            ),
            "template_attribute={0}".format(repr(self.template_attribute))
        ])
        return "DeriveKeyRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            "object_type": self.object_type,
            "unique_identifiers": self.unique_identifiers,
            "derivation_method": self.derivation_method,
            "derivation_parameters": self.derivation_parameters,
            "template_attribute": self.template_attribute
        })

class DeriveKeyResponsePayload(base.ResponsePayload):
    """
    A response payload for the DeriveKey operation.

    Attributes:
        unique_identifier: The unique ID of the newly derived cryptographic
            object.
        template_attribute: A collection of attributes that were implicitly
            set by the server on the newly derived cryptographic object.
    """

    def __init__(self,
                 unique_identifier=None,
                 template_attribute=None):
        """
        Construct a DeriveKey response payload struct.

        Args:
            unique_identifier (string): A string representing the ID of the
                newly derived managed object. Optional, defaults to None. At
                least one value is required for encoding and decoding.
            template_attribute (TemplateAttribute): A structure containing a
                set of attributes (e.g., cryptographic algorithm,
                cryptographic length) implicitly set by the server on the
                newly derived cryptographic object. Optional, defaults to
                None.
        """
        super(DeriveKeyResponsePayload, self).__init__()

        self._unique_identifier = None
        self._template_attribute = None

        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute

    @property
    def unique_identifier(self):
        if self._unique_identifier:
            return self._unique_identifier.value
        else:
            return None

    @unique_identifier.setter
    def unique_identifier(self, value):
        if value is None:
            self._unique_identifier = None
        elif isinstance(value, str):
            self._unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("Unique identifier must be a string.")

    @property
    def template_attribute(self):
        if self._template_attribute:
            return self._template_attribute
        else:
            return None

    @template_attribute.setter
    def template_attribute(self, value):
        if value is None:
            self._template_attribute = None
        elif isinstance(value, objects.TemplateAttribute):
            self._template_attribute = value
        else:
            raise TypeError(
                "Template attribute must be a TemplateAttribute structure."
            )

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the DeriveKey response payload and decode it
        into its constituent parts.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(DeriveKeyResponsePayload, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_buffer):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The DeriveKey response payload encoding is missing the "
                "unique identifier."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_buffer):
                self._template_attribute = objects.TemplateAttribute()
                self._template_attribute.read(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the DeriveKey response payload to a stream.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_buffer = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The DeriveKey response payload is missing the unique "
                "identifier field."
            )

        if kmip_version < enums.KMIPVersion.KMIP_2_0:
            if self._template_attribute:
                self._template_attribute.write(
                    local_buffer,
                    kmip_version=kmip_version
                )

        self.length = local_buffer.length()
        super(DeriveKeyResponsePayload, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __eq__(self, other):
        if isinstance(other, DeriveKeyResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.template_attribute != other.template_attribute:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DeriveKeyResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "template_attribute={0}".format(repr(self.template_attribute))
        ])
        return "DeriveKeyResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            "unique_identifier": self.unique_identifier,
            "template_attribute": self.template_attribute
        })
