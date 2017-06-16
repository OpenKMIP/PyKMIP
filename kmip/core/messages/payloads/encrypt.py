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
from kmip.core import primitives
from kmip.core import utils


class EncryptRequestPayload(primitives.Struct):
    """
    A request payload for the Encrypt operation.

    Attributes:
        unique_identifier: The unique ID of the managed object to be used for
            encryption.
        cryptographic_parameters: A collection of settings relevant for
            the encryption operation.
        data: The data to be encrypted in the form of a binary string.
        iv_counter_nonce: An IV/counter/nonce to be used with the encryption
            algorithm. Comes in the form of a binary string.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 data=None,
                 iv_counter_nonce=None):
        """
        Construct an Encrypt request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) to be used for encryption. Optional, defaults
                to None. If not included, the ID placeholder will be used.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the encryption algorithm. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
            data (bytes): The data to encrypt in binary form. Required for
                encoding and decoding.
            iv_counter_nonce (bytes): The IV/counter/nonce value to be used
                with the encryption algorithm. Optional, defaults to None.
        """
        super(EncryptRequestPayload, self).__init__(
            enums.Tags.REQUEST_PAYLOAD
        )

        self._unique_identifier = None
        self._cryptographic_parameters = None
        self._data = None
        self._iv_counter_nonce = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.iv_counter_nonce = iv_counter_nonce

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
        elif isinstance(value, six.binary_type):
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
        elif isinstance(value, six.binary_type):
            self._iv_counter_nonce = primitives.ByteString(
                value=value,
                tag=enums.Tags.IV_COUNTER_NONCE
            )
        else:
            raise TypeError("IV/counter/nonce must be bytes")

    def read(self, input_stream):
        """
        Read the data encoding the Encrypt request payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(EncryptRequestPayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(local_stream)

        if self.is_tag_next(
                enums.Tags.CRYPTOGRAPHIC_PARAMETERS,
                local_stream
        ):
            self._cryptographic_parameters = \
                attributes.CryptographicParameters()
            self._cryptographic_parameters.read(local_stream)

        if self.is_tag_next(enums.Tags.DATA, local_stream):
            self._data = primitives.ByteString(tag=enums.Tags.DATA)
            self._data.read(local_stream)
        else:
            raise ValueError("invalid payload missing the data attribute")

        if self.is_tag_next(enums.Tags.IV_COUNTER_NONCE, local_stream):
            self._iv_counter_nonce = primitives.ByteString(
                tag=enums.Tags.IV_COUNTER_NONCE
            )
            self._iv_counter_nonce.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Encrypt request payload to a stream.

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
        if self._cryptographic_parameters:
            self._cryptographic_parameters.write(local_stream)

        if self._data:
            self._data.write(local_stream)
        else:
            raise ValueError("invalid payload missing the data attribute")

        if self._iv_counter_nonce:
            self._iv_counter_nonce.write(local_stream)

        self.length = local_stream.length()
        super(EncryptRequestPayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, EncryptRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters !=\
                    other.cryptographic_parameters:
                return False
            elif self.data != other.data:
                return False
            elif self.iv_counter_nonce != other.iv_counter_nonce:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, EncryptRequestPayload):
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
            "iv_counter_nonce={0}".format(self.iv_counter_nonce)
        ])
        return "EncryptRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters,
            'data': self.data,
            'iv_counter_nonce': self.iv_counter_nonce
        })


class EncryptResponsePayload(primitives.Struct):
    """
    A response payload for the Encrypt operation.

    Attributes:
        unique_identifier: The unique ID of the managed object used for the
            encryption.
        data: The encrypted data in the form of a binary string.
        iv_counter_nonce: The IV/counter/nonce used with the encryption
            algorithm. Comes in the form of a binary string.
    """

    def __init__(self,
                 unique_identifier=None,
                 data=None,
                 iv_counter_nonce=None):
        """
        Construct an Encrypt response payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) used for encryption. Required for encoding
                and decoding.
            data (bytes): The encrypted data in binary form. Required for
                encoding and decoding.
            iv_counter_nonce (bytes): The IV/counter/nonce value used with
                the encryption algorithm if it was required and if this
                value was not originally specified by the client. Optional,
                defaults to None.
        """
        super(EncryptResponsePayload, self).__init__(
            enums.Tags.RESPONSE_PAYLOAD
        )

        self._unique_identifier = None
        self._data = None
        self._iv_counter_nonce = None

        self.unique_identifier = unique_identifier
        self.data = data
        self.iv_counter_nonce = iv_counter_nonce

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
    def data(self):
        if self._data:
            return self._data.value
        else:
            return None

    @data.setter
    def data(self, value):
        if value is None:
            self._data = None
        elif isinstance(value, six.binary_type):
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
        elif isinstance(value, six.binary_type):
            self._iv_counter_nonce = primitives.ByteString(
                value=value,
                tag=enums.Tags.IV_COUNTER_NONCE
            )
        else:
            raise TypeError("IV/counter/nonce must be bytes")

    def read(self, input_stream):
        """
        Read the data encoding the Encrypt response payload and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the unique_identifier or data attributes
                are missing from the encoded payload.
        """
        super(EncryptResponsePayload, self).read(input_stream)
        local_stream = utils.BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(local_stream)
        else:
            raise ValueError(
                "invalid payload missing the unique identifier attribute"
            )

        if self.is_tag_next(enums.Tags.DATA, local_stream):
            self._data = primitives.ByteString(tag=enums.Tags.DATA)
            self._data.read(local_stream)
        else:
            raise ValueError("invalid payload missing the data attribute")

        if self.is_tag_next(enums.Tags.IV_COUNTER_NONCE, local_stream):
            self._iv_counter_nonce = primitives.ByteString(
                tag=enums.Tags.IV_COUNTER_NONCE
            )
            self._iv_counter_nonce.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Encrypt response payload to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the unique_identifier or data attributes
                are not defined.
        """
        local_stream = utils.BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(local_stream)
        else:
            raise ValueError(
                "invalid payload missing the unique identifier attribute"
            )

        if self._data:
            self._data.write(local_stream)
        else:
            raise ValueError("invalid payload missing the data attribute")

        if self._iv_counter_nonce:
            self._iv_counter_nonce.write(local_stream)

        self.length = local_stream.length()
        super(EncryptResponsePayload, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, EncryptResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.data != other.data:
                return False
            elif self.iv_counter_nonce != other.iv_counter_nonce:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, EncryptResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "data={0}".format(self.data),
            "iv_counter_nonce={0}".format(self.iv_counter_nonce)
        ])
        return "EncryptResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'data': self.data,
            'iv_counter_nonce': self.iv_counter_nonce
        })
