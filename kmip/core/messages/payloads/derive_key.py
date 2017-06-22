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

import six

from kmip.core import attributes
from kmip.core import enums
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils


class DeriveKeyRequestPayload(primitives.Struct):
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
            object_type (ObjectType): An enumeration specifying the type of
                the object to derive. Optional, defaults to None. Required
                for encoding and decoding.
            unique_identifiers (list): A list of strings representing the IDs
                of managed objects (e.g., symmetric keys) to be used for
                derivation. Optional, defaults to None. At least one value is
                required for encoding and decoding.
            derivation_method (DerivationMethod): An enumeration specifying
                the type of derivation function to use (e.g., PBKDF2).
                Optional, defaults to None. Required for encoding and
                decoding.
            derivation_parameters (DerivationParameters): A structure
                containing cryptographic settings relevant for the derivation
                method. Optional, defaults to None. Required for encoding and
                decoding.
            template_attribute (TemplateAttribute): A structure containing a
                set of attributes (e.g., cryptographic algorithm,
                cryptographic length) that should be set on the newly derived
                cryptographic object. Optional, defaults to None. Required
                for encoding and decoding.
        """
        super(DeriveKeyRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD
        )

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
            raise TypeError("object type must be an ObjectType enumeration")

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
                if isinstance(i, six.string_types):
                    unique_identifiers.append(
                        primitives.TextString(
                            value=i,
                            tag=enums.Tags.UNIQUE_IDENTIFIER
                        )
                    )
                else:
                    raise TypeError(
                        "unique identifiers must be a list of strings"
                    )
            self._unique_identifiers = unique_identifiers
        else:
            raise TypeError("unique identifiers must be a list of strings")

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
                "derivation method must be a DerivationMethod enumeration"
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
                "derivation parameters must be a DerivationParameters struct"
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
                "template attribute must be a TemplateAttribute struct"
            )

    def read(self, input_stream):
        """
        Read the data encoding the DeriveKey request payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(DeriveKeyRequestPayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.OBJECT_TYPE, local_stream):
            self._object_type = primitives.Enumeration(
                enums.ObjectType,
                tag=enums.Tags.OBJECT_TYPE
            )
            self._object_type.read(local_stream)
        else:
            raise ValueError(
                "invalid payload missing object type"
            )

        unique_identifiers = []
        while self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            unique_identifier.read(local_stream)
            unique_identifiers.append(unique_identifier)
        if not unique_identifiers:
            raise ValueError("invalid payload missing unique identifiers")
        else:
            self._unique_identifiers = unique_identifiers

        if self.is_tag_next(enums.Tags.DERIVATION_METHOD, local_stream):
            self._derivation_method = primitives.Enumeration(
                enums.DerivationMethod,
                tag=enums.Tags.DERIVATION_METHOD
            )
            self._derivation_method.read(local_stream)
        else:
            raise ValueError(
                "invalid payload missing derivation method"
            )

        if self.is_tag_next(enums.Tags.DERIVATION_PARAMETERS, local_stream):
            self._derivation_parameters = attributes.DerivationParameters()
            self._derivation_parameters.read(local_stream)
        else:
            raise ValueError(
                "invalid payload missing derivation parameters"
            )

        if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_stream):
            self._template_attribute = objects.TemplateAttribute()
            self._template_attribute.read(local_stream)
        else:
            raise ValueError(
                "invalid payload missing template attribute"
            )

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the DeriveKey request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._object_type:
            self._object_type.write(local_stream)
        else:
            raise ValueError("invalid payload missing object type")

        if self._unique_identifiers:
            for unique_identifier in self._unique_identifiers:
                unique_identifier.write(local_stream)
        else:
            raise ValueError("invalid payload missing unique identifiers")

        if self._derivation_method:
            self._derivation_method.write(local_stream)
        else:
            raise ValueError("invalid payload missing derivation method")

        if self._derivation_parameters:
            self._derivation_parameters.write(local_stream)
        else:
            raise ValueError("invalid payload missing derivation parameters")

        if self._template_attribute:
            self._template_attribute.write(local_stream)
        else:
            raise ValueError("invalid payload missing template attributes")

        self.length = local_stream.length()
        super(DeriveKeyRequestPayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

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
            'object_type': self.object_type,
            'unique_identifiers': self.unique_identifiers,
            'derivation_method': self.derivation_method,
            'derivation_parameters': self.derivation_parameters,
            'template_attribute': self.template_attribute
        })


class DeriveKeyResponsePayload(primitives.Struct):
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
        super(DeriveKeyResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD
        )

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
        elif isinstance(value, six.string_types):
            self._unique_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
        else:
            raise TypeError("unique identifier must be a string")

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
                "template attribute must be a TemplateAttribute struct"
            )

    def read(self, input_stream):
        """
        Read the data encoding the DeriveKey response payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(DeriveKeyResponsePayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(local_stream)
        else:
            raise ValueError(
                "invalid payload missing unique identifier"
            )

        if self.is_tag_next(enums.Tags.TEMPLATE_ATTRIBUTE, local_stream):
            self._template_attribute = objects.TemplateAttribute()
            self._template_attribute.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the DeriveKey response payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(local_stream)
        else:
            raise ValueError(
                "invalid payload missing unique identifier"
            )

        if self._template_attribute:
            self._template_attribute.write(local_stream)

        self.length = local_stream.length()
        super(DeriveKeyResponsePayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

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
            'unique_identifier': self.unique_identifier,
            'template_attribute': self.template_attribute
        })
