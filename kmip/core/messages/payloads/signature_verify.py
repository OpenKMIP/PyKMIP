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

class SignatureVerifyRequestPayload(base.RequestPayload):
    """
    A request payload for the SignatureVerify operation.

    Attributes:
        unique_identifier: The unique ID of the key to use for signature
            verification.
        cryptographic_parameters: A collection of settings relevant for the
            signature verification process.
        data: The data that was signed.
        digested_data: The digested data to be verified.
        signature_data: The signature to be verified.
        correlation_value: An identifier for an existing, incomplete operation
            this payload hooks into.
        init_indicator: A boolean indicating whether or not the payload is the
            first in a series for a multi-payload operation.
        final_indicator: A boolean indicating whether or not the payload is
            the last in a series for a multi-payload operation.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None,
                 data=None,
                 digested_data=None,
                 signature_data=None,
                 correlation_value=None,
                 init_indicator=None,
                 final_indicator=None):
        """
        Construct a SignatureVerify request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) to be used for signature verification. Optional,
                defaults to None.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the signature verification operation. Optional, defaults to
                None.
            data (bytes): The bytes representing the original data that was
                signed. Optional, defaults to None.
            digested_data (bytes): The bytes representing the digested data to
                be verified with the signature. Optional, defaults to None.
            signature_data (bytes): The bytes representing the signature to be
                verified. Optional, defaults to None.
            correlation_value (bytes): The bytes representing a correlation
                value, allowing the linking together of individual payloads
                for a single overarching operation. Optional, defaults to None.
            init_indicator (boolean): A boolean value indicating whether or not
                the payload is the first in a series for a multi-payload
                operation. Optional, defaults to None.
            final_indicator (boolean): A boolean value indicating whether or
                not the payload is the last in a series for a multi-payload
                operation. Optional, defaults to None.
        """
        super(SignatureVerifyRequestPayload, self).__init__()

        self._unique_identifier = None
        self._cryptographic_parameters = None
        self._data = None
        self._digested_data = None
        self._signature_data = None
        self._correlation_value = None
        self._init_indicator = None
        self._final_indicator = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.digested_data = digested_data
        self.signature_data = signature_data
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator

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
                "Cryptographic parameters must be a CryptographicParameters "
                "struct."
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
            raise TypeError("Data must be bytes.")

    @property
    def digested_data(self):
        if self._digested_data:
            return self._digested_data.value
        else:
            return None

    @digested_data.setter
    def digested_data(self, value):
        if value is None:
            self._digested_data = None
        elif isinstance(value, bytes):
            self._digested_data = primitives.ByteString(
                value=value,
                tag=enums.Tags.DIGESTED_DATA
            )
        else:
            raise TypeError("Digested data must be bytes.")

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
            raise TypeError("Signature data must be bytes.")

    @property
    def correlation_value(self):
        if self._correlation_value:
            return self._correlation_value.value
        else:
            return None

    @correlation_value.setter
    def correlation_value(self, value):
        if value is None:
            self._correlation_value = None
        elif isinstance(value, bytes):
            self._correlation_value = primitives.ByteString(
                value=value,
                tag=enums.Tags.CORRELATION_VALUE
            )
        else:
            raise TypeError("Correlation value must be bytes.")

    @property
    def init_indicator(self):
        if self._init_indicator:
            return self._init_indicator.value
        else:
            return None

    @init_indicator.setter
    def init_indicator(self, value):
        if value is None:
            self._init_indicator = None
        elif isinstance(value, bool):
            self._init_indicator = primitives.Boolean(
                value=value,
                tag=enums.Tags.INIT_INDICATOR
            )
        else:
            raise TypeError("Init indicator must be a boolean.")

    @property
    def final_indicator(self):
        if self._final_indicator:
            return self._final_indicator.value
        else:
            return None

    @final_indicator.setter
    def final_indicator(self, value):
        if value is None:
            self._final_indicator = None
        elif isinstance(value, bool):
            self._final_indicator = primitives.Boolean(
                value=value,
                tag=enums.Tags.FINAL_INDICATOR
            )
        else:
            raise TypeError("Final indicator must be a boolean.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the SignatureVerify request payload and decode
        it into its constituent parts.

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
        super(SignatureVerifyRequestPayload, self).read(
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
        if self.is_tag_next(enums.Tags.CRYPTOGRAPHIC_PARAMETERS, local_stream):
            self._cryptographic_parameters = \
                attributes.CryptographicParameters()
            self._cryptographic_parameters.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(enums.Tags.DATA, local_stream):
            self._data = primitives.ByteString(tag=enums.Tags.DATA)
            self._data.read(local_stream, kmip_version=kmip_version)
        if self.is_tag_next(enums.Tags.DIGESTED_DATA, local_stream):
            self._digested_data = primitives.ByteString(
                tag=enums.Tags.DIGESTED_DATA
            )
            self._digested_data.read(local_stream, kmip_version=kmip_version)
        if self.is_tag_next(enums.Tags.SIGNATURE_DATA, local_stream):
            self._signature_data = primitives.ByteString(
                tag=enums.Tags.SIGNATURE_DATA
            )
            self._signature_data.read(local_stream, kmip_version=kmip_version)
        if self.is_tag_next(enums.Tags.CORRELATION_VALUE, local_stream):
            self._correlation_value = primitives.ByteString(
                tag=enums.Tags.CORRELATION_VALUE
            )
            self._correlation_value.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(enums.Tags.INIT_INDICATOR, local_stream):
            self._init_indicator = primitives.Boolean(
                tag=enums.Tags.INIT_INDICATOR
            )
            self._init_indicator.read(local_stream, kmip_version=kmip_version)
        if self.is_tag_next(enums.Tags.FINAL_INDICATOR, local_stream):
            self._final_indicator = primitives.Boolean(
                tag=enums.Tags.FINAL_INDICATOR
            )
            self._final_indicator.read(local_stream, kmip_version=kmip_version)

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the SignatureVerify request payload to a
        stream.

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
        if self._digested_data:
            self._digested_data.write(local_stream, kmip_version=kmip_version)
        if self._signature_data:
            self._signature_data.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._correlation_value:
            self._correlation_value.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._init_indicator:
            self._init_indicator.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._final_indicator:
            self._final_indicator.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(SignatureVerifyRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, SignatureVerifyRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters != \
                    other.cryptographic_parameters:
                return False
            elif self.data != other.data:
                return False
            elif self.digested_data != other.digested_data:
                return False
            elif self.signature_data != other.signature_data:
                return False
            elif self.correlation_value != other.correlation_value:
                return False
            elif self.init_indicator != other.init_indicator:
                return False
            elif self.final_indicator != other.final_indicator:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SignatureVerifyRequestPayload):
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
            "digested_data={0}".format(self.digested_data),
            "signature_data={0}".format(self.signature_data),
            "correlation_value={0}".format(self.correlation_value),
            "init_indicator={0}".format(self.init_indicator),
            "final_indicator={0}".format(self.final_indicator)
        ])
        return "SignatureVerifyRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters,
            'data': self.data,
            'digested_data': self.digested_data,
            'signature_data': self.signature_data,
            'correlation_value': self.correlation_value,
            'init_indicator': self.init_indicator,
            'final_indicator': self.final_indicator
        })

class SignatureVerifyResponsePayload(base.ResponsePayload):
    """
    A response payload for the SignatureVerify operation.

    Attributes:
        unique_identifier: The unique ID of the key used for signature
            verification.
        validity_indicator: The validity of the verified signature.
        data: Recovered data produced by the signature verification process.
        correlation_value: An identifier for an existing, incomplete operation
            this payload is a part of.
    """

    def __init__(self,
                 unique_identifier=None,
                 validity_indicator=None,
                 data=None,
                 correlation_value=None):
        """
        Construct a SignatureVerify response payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) used for signature verification. Optional,
                defaults to None. Required for read/write.
            validity_indicator (ValidityIndicator): A ValidityIndicator
                enumeration that specifies the validity of the signature.
                Optional, defaults to None. Required for read/write.
            data (bytes): The bytes representing any data recovered during the
                signature verification process. Optional, defaults to None.
            correlation_value (bytes): The bytes representing a correlation
                value, allowing the linking together of individual payloads
                for a single overarching operation. Optional, defaults to None.
        """
        super(SignatureVerifyResponsePayload, self).__init__()

        self._unique_identifier = None
        self._validity_indicator = None
        self._data = None
        self._correlation_value = None

        self.unique_identifier = unique_identifier
        self.validity_indicator = validity_indicator
        self.data = data
        self.correlation_value = correlation_value

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
    def validity_indicator(self):
        if self._validity_indicator:
            return self._validity_indicator.value
        else:
            return None

    @validity_indicator.setter
    def validity_indicator(self, value):
        if value is None:
            self._validity_indicator = None
        elif isinstance(value, enums.ValidityIndicator):
            self._validity_indicator = primitives.Enumeration(
                enums.ValidityIndicator,
                value=value,
                tag=enums.Tags.VALIDITY_INDICATOR
            )
        else:
            raise TypeError(
                "Validity indicator must be a ValidityIndicator enumeration."
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
            raise TypeError("Data must be bytes.")

    @property
    def correlation_value(self):
        if self._correlation_value:
            return self._correlation_value.value
        else:
            return None

    @correlation_value.setter
    def correlation_value(self, value):
        if value is None:
            self._correlation_value = None
        elif isinstance(value, bytes):
            self._correlation_value = primitives.ByteString(
                value=value,
                tag=enums.Tags.CORRELATION_VALUE
            )
        else:
            raise TypeError("Correlation value must be bytes.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the SignatureVerify response payload and decode
        it into its constituent parts.

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
        super(SignatureVerifyResponsePayload, self).read(
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
                "Parsed payload encoding is missing the unique identifier "
                "field."
            )
        if self.is_tag_next(enums.Tags.VALIDITY_INDICATOR, local_stream):
            self._validity_indicator = primitives.Enumeration(
                enums.ValidityIndicator,
                tag=enums.Tags.VALIDITY_INDICATOR
            )
            self._validity_indicator.read(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Parsed payload encoding is missing the validity indicator "
                "field."
            )
        if self.is_tag_next(enums.Tags.DATA, local_stream):
            self._data = primitives.ByteString(tag=enums.Tags.DATA)
            self._data.read(local_stream, kmip_version=kmip_version)
        if self.is_tag_next(enums.Tags.CORRELATION_VALUE, local_stream):
            self._correlation_value = primitives.ByteString(
                tag=enums.Tags.CORRELATION_VALUE
            )
            self._correlation_value.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the SignatureVerify response payload to a
        stream.

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
        else:
            raise ValueError(
                "Payload is missing the unique identifier field."
            )
        if self._validity_indicator:
            self._validity_indicator.write(
                local_stream,
                kmip_version=kmip_version
            )
        else:
            raise ValueError(
                "Payload is missing the validity indicator field."
            )
        if self._data:
            self._data.write(local_stream, kmip_version=kmip_version)
        if self._correlation_value:
            self._correlation_value.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(SignatureVerifyResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, SignatureVerifyResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.validity_indicator != other.validity_indicator:
                return False
            elif self.data != other.data:
                return False
            elif self.correlation_value != other.correlation_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SignatureVerifyResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "validity_indicator={0}".format(self.validity_indicator),
            "data={0}".format(self.data),
            "correlation_value={0}".format(self.correlation_value)
        ])
        return "SignatureVerifyResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'validity_indicator': self.validity_indicator,
            'data': self.data,
            'correlation_value': self.correlation_value
        })
