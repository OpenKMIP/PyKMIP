# Copyright (c) 2017 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
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

class SignRequestPayload(base.RequestPayload):
    """
    A request payload for the Sign operation.

    Attributes:
        unique_identifier: The unique ID of the managed object to be used for
            signing some data.
        cryptographic_parameters: A collection of settings relevant for the
            signature operation.
        data: The data to be signed in the form of a binary string.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 data=None):
        """
        Construct a Sign request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g. a
                public key) to be used for encryption. Optional, defaults to
                None. If not included, the ID placeholder will be used.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the signature algorithm. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
            data (bytes): The data to be signed, in binary form.
        """
        super(SignRequestPayload, self).__init__()

        self._unique_identifier = None
        self._cryptographic_parameters = None
        self._data = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
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
            self._data is None
        elif isinstance(value, bytes):
            self._data = primitives.ByteString(
                value=value,
                tag=enums.Tags.DATA
            )
        else:
            raise TypeError("data must be bytes")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Sign request payload and decode it
        into its parts

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the data attribute is missing from the
                encoded payload.
        """
        super(SignRequestPayload, self).read(
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
            raise ValueError(
                "invalid payload missing the data attribute"
            )

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Sign request payload to a stream.

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

        self.length = local_stream.length()
        super(SignRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, SignRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters !=\
                    other.cryptographic_parameters:
                return False
            elif self.data != other.data:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SignRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "cryptographic_parameters={0}".format(
                repr(self.cryptographic_parameters)
            ),
            "data={0}".format(self.data)
        ])
        return "SignRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters,
            'data': self.data
        })

class SignResponsePayload(base.ResponsePayload):
    """
    A response payload for the Sign operation.

    Attributes:
        unique_identifier: The unique ID of the managed object used to sign
            the data.
        signature_data: The signature data as a byte string.
    """

    def __init__(self,
                 unique_identifier=None,
                 signature_data=None):
        super(SignResponsePayload, self).__init__()

        self._unique_identifier = None
        self._signature_data = None

        self.unique_identifier = unique_identifier
        self.signature_data = signature_data

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
    def signature_data(self):
        if self._signature_data:
            return self._signature_data.value
        else:
            return None

    @signature_data.setter
    def signature_data(self, value):
        if value is None:
            self._signature_data = None
        elif isinstance(value, bytes):
            self._signature_data = primitives.ByteString(
                value=value,
                tag=enums.Tags.SIGNATURE_DATA
            )
        else:
            raise TypeError("signature data must be bytes")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Sign response payload and decode it.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.

        Raises:
            ValueError: Raised if the unique_identifier or signature attributes
                are missing from the encoded payload.
        """

        super(SignResponsePayload, self).read(
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

        if self.is_tag_next(enums.Tags.SIGNATURE_DATA, local_stream):
            self._signature_data = primitives.ByteString(
                tag=enums.Tags.SIGNATURE_DATA
            )
            self._signature_data.read(local_stream, kmip_version=kmip_version)
        else:
            raise ValueError(
                "invalid payload missing the signature data attribute"
            )

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Sign response to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the unique_identifier or signature
                attributes are not defined.
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

        if self._signature_data:
            self._signature_data.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "invalid payload missing the signature attribute"
            )

        self.length = local_stream.length()
        super(SignResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, SignResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.signature_data != other.signature_data:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SignResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "signature_data={0}".format(self.signature_data)
        ])
        return "SignResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'signature_data': self.signature_data
        })
