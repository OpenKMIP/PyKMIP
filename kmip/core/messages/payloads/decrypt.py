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
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class DecryptRequestPayload(base.RequestPayload):
    """
    A request payload for the Decrypt operation.

    Attributes:
        unique_identifier: The unique ID of the managed object to be used for
            decryption.
        cryptographic_parameters: A collection of settings relevant for
            the decryption operation.
        data: The data to be decrypted in the form of a binary string.
        iv_counter_nonce: An IV/counter/nonce to be used with the decryption
            algorithm. Comes in the form of a binary string.
        auth_additional_data: Any additional data to be authenticated via the
            Authenticated Encryption Tag. Added in KMIP 1.4.
        auth_tag: Specifies the tag that will be needed to
            authenticate the decrypted data. Only returned on completion
            of the encryption of the last of the plaintext by an
            authenticated encryption cipher. Optional, defaults to None.
            Added in KMIP 1.4.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 data=None,
                 iv_counter_nonce=None,
                 auth_additional_data=None,
                 auth_tag=None):
        """
        Construct a Decrypt request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) to be used for decryption. Optional, defaults
                to None. If not included, the ID placeholder will be used.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the decryption algorithm. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
            data (bytes): The data to decrypt in binary form. Required for
                encoding and decoding.
            iv_counter_nonce (bytes): The IV/counter/nonce value to be used
                with the decryption algorithm. Optional, defaults to None.
            auth_additional_data (bytes): Any additional data to be
                authenticated via the Authenticated Encryption Tag.
                Added in KMIP 1.4.
            auth_tag (bytes): Specifies the tag that will be needed to
                authenticate the decrypted data. Only returned on completion
                of the encryption of the last of the plaintext by an
                authenticated encryption cipher. Optional, defaults to None.
                Added in KMIP 1.4.
        """
        super(DecryptRequestPayload, self).__init__()

        self._unique_identifier = None
        self._cryptographic_parameters = None
        self._data = None
        self._iv_counter_nonce = None
        self._auth_additional_data = None
        self._auth_tag = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.iv_counter_nonce = iv_counter_nonce
        self.auth_additional_data = auth_additional_data
        self.auth_tag = auth_tag

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
            raise TypeError("unique identifier must be a string")

    @property
    def cryptographic_parameters(self):
        return self._cryptographic_parameters

    @cryptographic_parameters.setter
    def cryptographic_parameters(self, value):
        if value is None:
            self._cryptographic_parameters = None
        elif isinstance(value, attributes.CryptographicParameters):
            self._cryptographic_parameters = value
        else:
            raise TypeError(
                "cryptographic parameters must be a CryptographicParameters "
                "struct"
            )

    @property
    def data(self):
        if self._data:
            return self._data.value
        else:
            return None

    @data.setter
    def data(self, value):
        if value is None:
            self._data = None
        elif isinstance(value, bytes):
            self._data = primitives.ByteString(
                value=value,
                tag=enums.Tags.DATA
            )
        else:
            raise TypeError("data must be bytes")

    @property
    def iv_counter_nonce(self):
        if self._iv_counter_nonce:
            return self._iv_counter_nonce.value
        else:
            return None

    @iv_counter_nonce.setter
    def iv_counter_nonce(self, value):
        if value is None:
            self._iv_counter_nonce = None
        elif isinstance(value, bytes):
            self._iv_counter_nonce = primitives.ByteString(
                value=value,
                tag=enums.Tags.IV_COUNTER_NONCE
            )
        else:
            raise TypeError("IV/counter/nonce must be bytes")

    @property
    def auth_additional_data(self):
        if self._auth_additional_data:
            return self._auth_additional_data.value
        else:
            return None

    @auth_additional_data.setter
    def auth_additional_data(self, value):
        if value is None:
            self._auth_additional_data = None
        elif isinstance(value, bytes):
            self._auth_additional_data = primitives.ByteString(
                value=value,
                tag=enums.Tags.AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA
            )
        else:
            raise TypeError("authenticated additional data must be bytes")

    @property
    def auth_tag(self):
        if self._auth_tag:
            return self._auth_tag.value
        else:
            return None

    @auth_tag.setter
    def auth_tag(self, value):
        if value is None:
            self._auth_tag = None
        elif isinstance(value, bytes):
            self._auth_tag = primitives.ByteString(
                value=value,
                tag=enums.Tags.AUTHENTICATED_ENCRYPTION_TAG
            )
        else:
            raise TypeError("authenticated encryption tag must be bytes")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Decrypt request payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(DecryptRequestPayload, self).read(
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

        if self.is_tag_next(
                enums.Tags.CRYPTOGRAPHIC_PARAMETERS,
                local_stream
        ):
            self._cryptographic_parameters = \
                attributes.CryptographicParameters()
            self._cryptographic_parameters.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.DATA, local_stream):
            self._data = primitives.ByteString(tag=enums.Tags.DATA)
            self._data.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("invalid payload missing the data attribute")

        if self.is_tag_next(enums.Tags.IV_COUNTER_NONCE, local_stream):
            self._iv_counter_nonce = primitives.ByteString(
                tag=enums.Tags.IV_COUNTER_NONCE
            )
            self._iv_counter_nonce.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(
                enums.Tags.AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
                local_stream
        ):
            self._auth_additional_data = primitives.ByteString(
                tag=enums.Tags.AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA
            )
            self._auth_additional_data.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(
                enums.Tags.AUTHENTICATED_ENCRYPTION_TAG, local_stream
        ):
            self._auth_tag = primitives.ByteString(
                tag=enums.Tags.AUTHENTICATED_ENCRYPTION_TAG
            )
            self._auth_tag.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Decrypt request payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._cryptographic_parameters:
            self._cryptographic_parameters.write(
                local_stream,
                kmip_version=kmip_version
            )

        if self._data:
            self._data.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("invalid payload missing the data attribute")

        if self._iv_counter_nonce:
            self._iv_counter_nonce.write(
                local_stream,
                kmip_version=kmip_version
            )

        if self._auth_additional_data:
            self._auth_additional_data.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._auth_tag:
            self._auth_tag.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(DecryptRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, DecryptRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters != \
                    other.cryptographic_parameters:
                return False
            elif self.data != other.data:
                return False
            elif self.iv_counter_nonce != other.iv_counter_nonce:
                return False
            elif self.auth_additional_data != other.auth_additional_data:
                return False
            elif self.auth_tag != other.auth_tag:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DecryptRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "cryptographic_parameters={0}".format(
                repr(self.cryptographic_parameters)
            ),
            "data={0}".format(self.data),
            "iv_counter_nonce={0}".format(self.iv_counter_nonce),
            "auth_additional_data={0}".format(self.auth_additional_data),
            "auth_tag={0}".format(self.auth_tag)
        ])
        return "DecryptRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters,
            'data': self.data,
            'iv_counter_nonce': self.iv_counter_nonce,
            'auth_additional_data': self.auth_additional_data,
            'auth_tag': self.auth_tag
        })

class DecryptResponsePayload(base.ResponsePayload):
    """
    A response payload for the Decrypt operation.

    Attributes:
        unique_identifier: The unique ID of the managed object used for the
            decryption.
        data: The decrypted data in the form of a binary string.
    """

    def __init__(self,
                 unique_identifier=None,
                 data=None):
        """
        Construct a Decrypt response payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) used for decryption. Required for encoding
                and decoding.
            data (bytes): The decrypted data in binary form. Required for
                encoding and decoding.
        """
        super(DecryptResponsePayload, self).__init__()

        self._unique_identifier = None
        self._data = None

        self.unique_identifier = unique_identifier
        self.data = data

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
            raise TypeError("unique identifier must be a string")

    @property
    def data(self):
        if self._data:
            return self._data.value
        else:
            return None

    @data.setter
    def data(self, value):
        if value is None:
            self._data = None
        elif isinstance(value, bytes):
            self._data = primitives.ByteString(
                value=value,
                tag=enums.Tags.DATA
            )
        else:
            raise TypeError("data must be bytes")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Decrypt response payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the unique_identifier or data attributes
                are missing from the encoded payload.
        """
        super(DecryptResponsePayload, self).read(
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
        else:
            raise ValueError(
                "invalid payload missing the unique identifier attribute"
            )

        if self.is_tag_next(enums.Tags.DATA, local_stream):
            self._data = primitives.ByteString(tag=enums.Tags.DATA)
            self._data.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("invalid payload missing the data attribute")

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Decrypt response payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the unique_identifier or data attributes
                are not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "invalid payload missing the unique identifier attribute"
            )

        if self._data:
            self._data.write(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError("invalid payload missing the data attribute")

        self.length = local_stream.length()
        super(DecryptResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, DecryptResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.data != other.data:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DecryptResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "data={0}".format(self.data)
        ])
        return "DecryptResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'data': self.data
        })
