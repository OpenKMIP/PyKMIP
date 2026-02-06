# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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
from kmip.core import objects
from kmip.core import primitives
from kmip.core import secrets
from kmip.core import utils
from kmip.core.factories import secrets as secret_factory
from kmip.core.messages.payloads import base

class GetRequestPayload(base.RequestPayload):
    """
    A request payload for the Get operation.

    Attributes:
        unique_identifier: The unique ID of the managed object to retrieve
            from the server.
        key_format_type: The format of the returned object, if it is a key.
        key_compression_type: The compression method to be used for the
            returned object, if it is an elliptic curve public key.
        key_wrapping_specification: A collection of settings specifying how
            the returned object should be cryptographically wrapped if it is
            a key.
    """

    def __init__(self,
                 unique_identifier=None,
                 key_format_type=None,
                 key_compression_type=None,
                 key_wrapping_specification=None):
        """
        Construct a Get request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g., a
                symmetric key) to retrieve. Optional, defaults to None.
            key_format_type (KeyFormatType): A KeyFormatType enumeration that
                specifies the format in which the object should be returned.
                Optional, defaults to None.
            key_compression_type (KeyCompressionType): A KeyCompressionType
                enumeration that specifies the compression method to be used
                when returning elliptic curve public keys. Optional, defaults
                to None.
            key_wrapping_specification (KeyWrappingSpecification): A
                KeyWrappingSpecification struct that specifies keys and other
                information for wrapping the returned object. Optional,
                defaults to None.
        """
        super(GetRequestPayload, self).__init__()

        self._unique_identifier = None
        self._key_format_type = None
        self._key_compression_type = None
        self._key_wrapping_specification = None

        self.unique_identifier = unique_identifier
        self.key_format_type = key_format_type
        self.key_compression_type = key_compression_type
        self.key_wrapping_specification = key_wrapping_specification

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
    def key_format_type(self):
        if self._key_format_type:
            return self._key_format_type.value
        else:
            return None

    @key_format_type.setter
    def key_format_type(self, value):
        if value is None:
            self._key_format_type = None
        elif isinstance(value, enums.KeyFormatType):
            self._key_format_type = primitives.Enumeration(
                enums.KeyFormatType,
                value=value,
                tag=enums.Tags.KEY_FORMAT_TYPE
            )
        else:
            raise TypeError(
                "Key format type must be a KeyFormatType enumeration."
            )

    @property
    def key_compression_type(self):
        if self._key_compression_type:
            return self._key_compression_type.value
        else:
            return None

    @key_compression_type.setter
    def key_compression_type(self, value):
        if value is None:
            self._key_compression_type = None
        elif isinstance(value, enums.KeyCompressionType):
            self._key_compression_type = primitives.Enumeration(
                enums.KeyCompressionType,
                value=value,
                tag=enums.Tags.KEY_COMPRESSION_TYPE
            )
        else:
            raise TypeError(
                "Key compression type must be a KeyCompressionType "
                "enumeration."
            )

    @property
    def key_wrapping_specification(self):
        return self._key_wrapping_specification

    @key_wrapping_specification.setter
    def key_wrapping_specification(self, value):
        if value is None:
            self._key_wrapping_specification = None
        elif isinstance(value, objects.KeyWrappingSpecification):
            self._key_wrapping_specification = value
        else:
            raise TypeError(
                "Key wrapping specification must be a "
                "KeyWrappingSpecification struct."
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Get request payload and decode it into its
        constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(GetRequestPayload, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.KEY_FORMAT_TYPE, local_stream):
            self._key_format_type = primitives.Enumeration(
                enum=enums.KeyFormatType,
                tag=enums.Tags.KEY_FORMAT_TYPE
            )
            self._key_format_type.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.KEY_COMPRESSION_TYPE, local_stream):
            self._key_compression_type = primitives.Enumeration(
                enum=enums.KeyCompressionType,
                tag=enums.Tags.KEY_COMPRESSION_TYPE
            )
            self._key_compression_type.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(
                enums.Tags.KEY_WRAPPING_SPECIFICATION,
                local_stream
        ):
            self._key_wrapping_specification = \
                objects.KeyWrappingSpecification()
            self._key_wrapping_specification.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Get request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier is not None:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._key_format_type is not None:
            self._key_format_type.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._key_compression_type is not None:
            self._key_compression_type.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._key_wrapping_specification is not None:
            self._key_wrapping_specification.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(GetRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, GetRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            elif self.key_compression_type != other.key_compression_type:
                return False
            elif self.key_wrapping_specification != \
                    other.key_wrapping_specification:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, GetRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "key_format_type={0}".format(self.key_format_type),
            "key_compression_type={0}".format(self.key_compression_type),
            "key_wrapping_specification={0}".format(
                repr(self.key_wrapping_specification)
            )
        ])
        return "GetRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'key_format_type': self.key_format_type,
            'key_compression_type': self.key_compression_type,
            'key_wrapping_specification': self.key_wrapping_specification
        })

class GetResponsePayload(base.ResponsePayload):
    """
    A response payload for the Get operation.

    Attributes:
        object_type: The type of the managed object being returned.
        unique_identifier: The unique ID of the managed object being returned.
        secret: The managed object being returned.
    """

    def __init__(self,
                 object_type=None,
                 unique_identifier=None,
                 secret=None):
        """
        Construct a Get response payload struct.

        Args:
            object_type (ObjectType): An ObjectType enumeration specifying the
                type of managed object being returned. Optional, defaults to
                None. Required for read/write.
            unique_identifier (string): The ID of the managed object (e.g., a
                symmetric key) being returned. Optional, defaults to None.
                Required for read/write.
            secret (various): The managed object struct being returned. Must
                be one of the following:

                Optional, defaults to None. Required for read/write.
        """
        super(GetResponsePayload, self).__init__()

        self._object_type = None
        self._unique_identifier = None
        self._secret = None

        self.object_type = object_type
        self.unique_identifier = unique_identifier
        self.secret = secret

        self.secret_factory = secret_factory.SecretFactory()

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
    def secret(self):
        return self._secret

    @secret.setter
    def secret(self, value):
        if value is None:
            self._secret = None
        elif isinstance(
                value,
                (
                    secrets.Certificate,
                    secrets.OpaqueObject,
                    secrets.PrivateKey,
                    secrets.PublicKey,
                    secrets.SecretData,
                    secrets.SplitKey,
                    secrets.SymmetricKey,
                    secrets.Template
                )
        ):
            self._secret = value
        else:
            raise TypeError(
                "Secret must be one of the following structs: Certificate, "
                "OpaqueObject, PrivateKey, PublicKey, SecretData, SplitKey, "
                "SymmetricKey, Template"
            )

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Get response payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the object type, unique identifier, or
                secret attributes are missing from the encoded payload.
        """
        super(GetResponsePayload, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.OBJECT_TYPE, local_stream):
            self._object_type = primitives.Enumeration(
                enum=enums.ObjectType,
                tag=enums.Tags.OBJECT_TYPE
            )
            self._object_type.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Parsed payload encoding is missing the object type field."
            )

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Parsed payload encoding is missing the unique identifier "
                "field."
            )

        self.secret = self.secret_factory.create(self.object_type)
        if self.is_tag_next(self._secret.tag, local_stream):
            self._secret.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "Parsed payload encoding is missing the secret field."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Get response payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the object type, unique identifier, or
                secret attributes are missing from the payload struct.
        """
        local_stream = utils.BytearrayStream()

        if self.object_type:
            self._object_type.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("Payload is missing the object type field.")

        if self.unique_identifier:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Payload is missing the unique identifier field."
            )

        if self.secret:
            self._secret.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("Payload is missing the secret field.")

        self.length = local_stream.length()
        super(GetResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, GetResponsePayload):
            if self.object_type != other.object_type:
                return False
            elif self.unique_identifier != other.unique_identifier:
                return False
            elif self.secret != other.secret:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, GetResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "object_type={0}".format(self.object_type),
            "unique_identifier='{0}'".format(self.unique_identifier),
            "secret={0}".format(repr(self.secret))
        ])
        return "GetResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'object_type': self.object_type,
            'unique_identifier': self.unique_identifier,
            'secret': self.secret
        })
