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

import abc
import six
from six.moves import xrange

from kmip.core import attributes
from kmip.core.attributes import CryptographicParameters

from kmip.core.factories.attribute_values import AttributeValueFactory

from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import Tags
from kmip.core.enums import Types
from kmip.core.enums import RevocationReasonCode as RevocationReasonCodeEnum
from kmip.core import exceptions

from kmip.core.misc import KeyFormatType

from kmip.core import primitives
from kmip.core.primitives import Struct
from kmip.core.primitives import TextString
from kmip.core.primitives import ByteString
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration

from kmip.core.utils import BytearrayStream


# 2.1
# 2.1.1
class Attribute(Struct):

    class AttributeName(TextString):

        def __init__(self, value=None):
            super(Attribute.AttributeName, self).__init__(
                value, Tags.ATTRIBUTE_NAME)

        def __eq__(self, other):
            if isinstance(other, Attribute.AttributeName):
                if self.value != other.value:
                    return False
                else:
                    return True
            else:
                NotImplemented

        def __ne__(self, other):
            if isinstance(other, Attribute.AttributeName):
                return not (self == other)
            else:
                return NotImplemented

    class AttributeIndex(Integer):

        def __init__(self, value=None):
            super(Attribute.AttributeIndex, self).__init__(
                value, Tags.ATTRIBUTE_INDEX)

    def __init__(self,
                 attribute_name=None,
                 attribute_index=None,
                 attribute_value=None):
        super(Attribute, self).__init__(tag=Tags.ATTRIBUTE)

        self.value_factory = AttributeValueFactory()

        self.attribute_name = attribute_name
        self.attribute_index = attribute_index
        self.attribute_value = attribute_value

        if attribute_value is not None:
            attribute_value.tag = Tags.ATTRIBUTE_VALUE

    def read(self, istream):
        super(Attribute, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the name of the attribute
        self.attribute_name = Attribute.AttributeName()
        self.attribute_name.read(tstream)

        # Read the attribute index if it is next
        if self.is_tag_next(Tags.ATTRIBUTE_INDEX, tstream):
            self.attribute_index = Attribute.AttributeIndex()
            self.attribute_index.read(tstream)

        # Lookup the attribute class that belongs to the attribute name
        name = self.attribute_name.value
        enum_name = name.replace('.', '_').replace(' ', '_').upper()
        enum_type = None

        try:
            enum_type = AttributeType[enum_name]
        except KeyError:
            # Likely custom attribute, pass raw name string as attribute type
            enum_type = name

        value = self.value_factory.create_attribute_value(enum_type, None)
        if value is None:
            raise Exception("No value type for {}".format(enum_name))
        self.attribute_value = value
        self.attribute_value.tag = Tags.ATTRIBUTE_VALUE
        self.attribute_value.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = BytearrayStream()

        self.attribute_name.write(tstream)
        if self.attribute_index is not None:
            self.attribute_index.write(tstream)
        self.attribute_value.write(tstream)

        # Write the length and value of the attribute
        self.length = tstream.length()
        super(Attribute, self).write(ostream)
        ostream.write(tstream.buffer)

    def __repr__(self):
        attribute_name = "attribute_name={0}".format(repr(self.attribute_name))
        attribute_index = "attribute_index={0}".format(
            repr(self.attribute_index)
        )
        attribute_value = "attribute_value={0}".format(
            repr(self.attribute_value)
        )
        return "Attribute({0}, {1}, {2})".format(
            attribute_name,
            attribute_index,
            attribute_value
        )

    def __str__(self):
        return str({
            'attribute_name': str(self.attribute_name),
            'attribute_index': str(self.attribute_index),
            'attribute_value': str(self.attribute_value)
        })

    def __eq__(self, other):
        if isinstance(other, Attribute):
            if self.attribute_name != other.attribute_name:
                return False
            elif self.attribute_index != other.attribute_index:
                return False
            elif self.attribute_value != other.attribute_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Attribute):
            return not self.__eq__(other)
        else:
            return NotImplemented


class Nonce(primitives.Struct):
    """
    A struct representing a Nonce object.

    Attributes:
        nonce_id (bytes): A binary string representing the ID of the nonce
            value.
        nonce_value (bytes): A binary string representing a random value.
    """

    def __init__(self, nonce_id=None, nonce_value=None):
        """
        Construct a Nonce struct.

        Args:
            nonce_id (bytes): A binary string representing the ID of the nonce
                value. Optional, defaults to None. Required for encoding and
                decoding.
            nonce_value (bytes): A binary string representing a random value.
                Optional, defaults to None. Required for encoding and decoding.
        """
        super(Nonce, self).__init__(tag=enums.Tags.NONCE)

        self._nonce_id = None
        self._nonce_value = None

        self.nonce_id = nonce_id
        self.nonce_value = nonce_value

    @property
    def nonce_id(self):
        if self._nonce_id:
            return self._nonce_id.value
        else:
            return None

    @nonce_id.setter
    def nonce_id(self, value):
        if value is None:
            self._nonce_id = None
        elif isinstance(value, six.binary_type):
            self._nonce_id = primitives.ByteString(
                value=value,
                tag=enums.Tags.NONCE_ID
            )
        else:
            raise TypeError("Nonce ID must be bytes.")

    @property
    def nonce_value(self):
        if self._nonce_value:
            return self._nonce_value.value
        else:
            return None

    @nonce_value.setter
    def nonce_value(self, value):
        if value is None:
            self._nonce_value = None
        elif isinstance(value, six.binary_type):
            self._nonce_value = primitives.ByteString(
                value=value,
                tag=enums.Tags.NONCE_VALUE
            )
        else:
            raise TypeError("Nonce value must be bytes.")

    def read(self, input_stream):
        """
        Read the data encoding the Nonce struct and decode it into its
        constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the nonce ID or nonce value is missing from
                the encoding.
        """
        super(Nonce, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.NONCE_ID, local_stream):
            self._nonce_id = primitives.ByteString(
                tag=enums.Tags.NONCE_ID
            )
            self._nonce_id.read(local_stream)
        else:
            raise ValueError(
                "Nonce encoding missing the nonce ID."
            )

        if self.is_tag_next(enums.Tags.NONCE_VALUE, local_stream):
            self._nonce_value = primitives.ByteString(
                tag=enums.Tags.NONCE_VALUE
            )
            self._nonce_value.read(local_stream)
        else:
            raise ValueError(
                "Nonce encoding missing the nonce value."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Nonce struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the nonce ID or nonce value is not defined.
        """
        local_stream = BytearrayStream()

        if self._nonce_id:
            self._nonce_id.write(local_stream)
        else:
            raise ValueError("Nonce struct is missing the nonce ID.")

        if self._nonce_value:
            self._nonce_value.write(local_stream)
        else:
            raise ValueError("Nonce struct is missing the nonce value.")

        self.length = local_stream.length()
        super(Nonce, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, Nonce):
            if self.nonce_id != other.nonce_id:
                return False
            elif self.nonce_value != other.nonce_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Nonce):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "nonce_id={}".format(self.nonce_id),
            "nonce_value={}".format(self.nonce_value)
        ])
        return "Nonce({})".format(args)

    def __str__(self):
        body = ", ".join([
            "'nonce_id': {}".format(self.nonce_id),
            "'nonce_value': {}".format(self.nonce_value)
        ])
        return "{" + body + "}"


@six.add_metaclass(abc.ABCMeta)
class CredentialValue(primitives.Struct):
    """
    An empty, abstract base class to be used by Credential objects to easily
    group and type-check credential values.
    """


class UsernamePasswordCredential(CredentialValue):
    """
    A struct representing a UsernamePasswordCredential object.

    Attributes:
        username: The username identifying the credential.
        password: The password associated with the username.
    """

    def __init__(self, username=None, password=None):
        """
        Construct a UsernamePasswordCredential struct.

        Args:
            username (string): The username identifying the credential.
                Optional, defaults to None. Required for encoding and decoding.
            password (string): The password associated with the username.
                Optional, defaults to None.
        """
        super(UsernamePasswordCredential, self).__init__(
            tag=Tags.CREDENTIAL_VALUE
        )

        self._username = None
        self._password = None

        self.username = username
        self.password = password

    @property
    def username(self):
        if self._username:
            return self._username.value
        else:
            return None

    @username.setter
    def username(self, value):
        if value is None:
            self._username = None
        elif isinstance(value, six.string_types):
            self._username = primitives.TextString(
                value=value,
                tag=enums.Tags.USERNAME
            )
        else:
            raise TypeError("Username must be a string.")

    @property
    def password(self):
        if self._password:
            return self._password.value
        else:
            return None

    @password.setter
    def password(self, value):
        if value is None:
            self._password = None
        elif isinstance(value, six.string_types):
            self._password = primitives.TextString(
                value=value,
                tag=enums.Tags.PASSWORD
            )
        else:
            raise TypeError("Password must be a string.")

    def read(self, input_stream):
        """
        Read the data encoding the UsernamePasswordCredential struct and
        decode it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the username is missing from the encoding.
        """
        super(UsernamePasswordCredential, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.USERNAME, local_stream):
            self._username = primitives.TextString(
                tag=enums.Tags.USERNAME
            )
            self._username.read(local_stream)
        else:
            raise ValueError(
                "Username/password credential encoding missing the username."
            )

        if self.is_tag_next(enums.Tags.PASSWORD, local_stream):
            self._password = primitives.TextString(
                tag=enums.Tags.PASSWORD
            )
            self._password.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the UsernamePasswordCredential struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if the username is not defined.
        """
        local_stream = BytearrayStream()

        if self._username:
            self._username.write(local_stream)
        else:
            raise ValueError(
                "Username/password credential struct missing the username."
            )

        if self._password:
            self._password.write(local_stream)

        self.length = local_stream.length()
        super(UsernamePasswordCredential, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, UsernamePasswordCredential):
            if self.username != other.username:
                return False
            elif self.password != other.password:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, UsernamePasswordCredential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "username='{}'".format(self.username),
            "password='{}'".format(self.password)
        ])
        return "UsernamePasswordCredential({})".format(args)

    def __str__(self):
        return str({
            "username": self.username,
            "password": self.password
        })


class DeviceCredential(CredentialValue):
    """
    A struct representing a DeviceCredential object.

    Attributes:
        device_serial_number: The device serial number for the credential.
        password: The password associated with the credential.
        device_identifier: The device identifier for the credential.
        network_identifier: The network identifier for the credential.
        machine_identifier: The machine identifier for the credential.
        media_identifier: The media identifier for the credential.
    """

    def __init__(self,
                 device_serial_number=None,
                 password=None,
                 device_identifier=None,
                 network_identifier=None,
                 machine_identifier=None,
                 media_identifier=None):
        """
        Construct a DeviceCredential struct.

        Args:
            device_serial_number (string): The device serial number for the
                credential. Optional, defaults to None.
            password (string): The password associated with the credential.
                Optional, defaults to None.
            device_identifier (string): The device identifier for the
                credential. Optional, defaults to None.
            network_identifier (string): The network identifier for the
                credential. Optional, defaults to None.
            machine_identifier (string): The machine identifier for the
                credential. Optional, defaults to None.
            media_identifier (string): The media identifier for the
                credential. Optional, defaults to None.
        """
        super(DeviceCredential, self).__init__(tag=Tags.CREDENTIAL_VALUE)

        self._device_serial_number = None
        self._password = None
        self._device_identifier = None
        self._network_identifier = None
        self._machine_identifier = None
        self._media_identifier = None

        self.device_serial_number = device_serial_number
        self.password = password
        self.device_identifier = device_identifier
        self.network_identifier = network_identifier
        self.machine_identifier = machine_identifier
        self.media_identifier = media_identifier

    @property
    def device_serial_number(self):
        if self._device_serial_number:
            return self._device_serial_number.value
        else:
            return None

    @device_serial_number.setter
    def device_serial_number(self, value):
        if value is None:
            self._device_serial_number = None
        elif isinstance(value, six.string_types):
            self._device_serial_number = primitives.TextString(
                value=value,
                tag=enums.Tags.DEVICE_SERIAL_NUMBER
            )
        else:
            raise TypeError("Device serial number must be a string.")

    @property
    def password(self):
        if self._password:
            return self._password.value
        else:
            return None

    @password.setter
    def password(self, value):
        if value is None:
            self._password = None
        elif isinstance(value, six.string_types):
            self._password = primitives.TextString(
                value=value,
                tag=enums.Tags.PASSWORD
            )
        else:
            raise TypeError("Password must be a string.")

    @property
    def device_identifier(self):
        if self._device_identifier:
            return self._device_identifier.value
        else:
            return None

    @device_identifier.setter
    def device_identifier(self, value):
        if value is None:
            self._device_identifier = None
        elif isinstance(value, six.string_types):
            self._device_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.DEVICE_IDENTIFIER
            )
        else:
            raise TypeError("Device identifier must be a string.")

    @property
    def network_identifier(self):
        if self._network_identifier:
            return self._network_identifier.value
        else:
            return None

    @network_identifier.setter
    def network_identifier(self, value):
        if value is None:
            self._network_identifier = None
        elif isinstance(value, six.string_types):
            self._network_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.NETWORK_IDENTIFIER
            )
        else:
            raise TypeError("Network identifier must be a string.")

    @property
    def machine_identifier(self):
        if self._machine_identifier:
            return self._machine_identifier.value
        else:
            return None

    @machine_identifier.setter
    def machine_identifier(self, value):
        if value is None:
            self._machine_identifier = None
        elif isinstance(value, six.string_types):
            self._machine_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.MACHINE_IDENTIFIER
            )
        else:
            raise TypeError("Machine identifier must be a string.")

    @property
    def media_identifier(self):
        if self._media_identifier:
            return self._media_identifier.value
        else:
            return None

    @media_identifier.setter
    def media_identifier(self, value):
        if value is None:
            self._media_identifier = None
        elif isinstance(value, six.string_types):
            self._media_identifier = primitives.TextString(
                value=value,
                tag=enums.Tags.MEDIA_IDENTIFIER
            )
        else:
            raise TypeError("Media identifier must be a string.")

    def read(self, input_stream):
        """
        Read the data encoding the DeviceCredential struct and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object..
        """
        super(DeviceCredential, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.DEVICE_SERIAL_NUMBER, local_stream):
            self._device_serial_number = primitives.TextString(
                tag=enums.Tags.DEVICE_SERIAL_NUMBER
            )
            self._device_serial_number.read(local_stream)

        if self.is_tag_next(enums.Tags.PASSWORD, local_stream):
            self._password = primitives.TextString(
                tag=enums.Tags.PASSWORD
            )
            self._password.read(local_stream)

        if self.is_tag_next(enums.Tags.DEVICE_IDENTIFIER, local_stream):
            self._device_identifier = primitives.TextString(
                tag=enums.Tags.DEVICE_IDENTIFIER
            )
            self._device_identifier.read(local_stream)

        if self.is_tag_next(enums.Tags.NETWORK_IDENTIFIER, local_stream):
            self._network_identifier = primitives.TextString(
                tag=enums.Tags.NETWORK_IDENTIFIER
            )
            self._network_identifier.read(local_stream)

        if self.is_tag_next(enums.Tags.MACHINE_IDENTIFIER, local_stream):
            self._machine_identifier = primitives.TextString(
                tag=enums.Tags.MACHINE_IDENTIFIER
            )
            self._machine_identifier.read(local_stream)

        if self.is_tag_next(enums.Tags.MEDIA_IDENTIFIER, local_stream):
            self._media_identifier = primitives.TextString(
                tag=enums.Tags.MEDIA_IDENTIFIER
            )
            self._media_identifier.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the DeviceCredential struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
        """
        local_stream = BytearrayStream()

        if self._device_serial_number is not None:
            self._device_serial_number.write(local_stream)
        if self._password is not None:
            self._password.write(local_stream)
        if self._device_identifier is not None:
            self._device_identifier.write(local_stream)
        if self._network_identifier is not None:
            self._network_identifier.write(local_stream)
        if self._machine_identifier is not None:
            self._machine_identifier.write(local_stream)
        if self._media_identifier is not None:
            self._media_identifier.write(local_stream)

        self.length = local_stream.length()
        super(DeviceCredential, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, DeviceCredential):
            if self.device_serial_number != other.device_serial_number:
                return False
            elif self.password != other.password:
                return False
            elif self.device_identifier != other.device_identifier:
                return False
            elif self.network_identifier != other.network_identifier:
                return False
            elif self.machine_identifier != other.machine_identifier:
                return False
            elif self.media_identifier != other.media_identifier:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, DeviceCredential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "device_serial_number='{}'".format(self.device_serial_number),
            "password='{}'".format(self.password),
            "device_identifier='{}'".format(self.device_identifier),
            "network_identifier='{}'".format(self.network_identifier),
            "machine_identifier='{}'".format(self.machine_identifier),
            "media_identifier='{}'".format(self.media_identifier),
        ])
        return "DeviceCredential({})".format(args)

    def __str__(self):
        return str({
            "device_serial_number": self.device_serial_number,
            "password": self.password,
            "device_identifier": self.device_identifier,
            "network_identifier": self.network_identifier,
            "machine_identifier": self.machine_identifier,
            "media_identifier": self.media_identifier
        })


class AttestationCredential(CredentialValue):
    """
    A struct representing an AttestationCredential object.

    Attributes:
        nonce: A nonce value obtained from the key management server.
        attestation_type: The type of attestation being used.
        attestation_measurement: The attestation measurement of the client.
        attestation_assertion: The attestation assertion from a third party.
    """

    def __init__(self,
                 nonce=None,
                 attestation_type=None,
                 attestation_measurement=None,
                 attestation_assertion=None):
        """
        Construct an AttestationCredential struct.

        Args:
            nonce (Nonce): A Nonce structure containing nonce data obtained
                from the key management server. Optional, defaults to None.
                Required for encoding and decoding.
            attestation_type (enum): An AttestationType enumeration specifying
                the type of attestation being used. Optional, defaults to None.
                Required for encoding and decoding.
            attestation_measurement (bytes): The device identifier for the
                credential. Optional, defaults to None. Required for encoding
                and decoding if the attestation assertion is not provided.
            attestation_assertion (bytes): The network identifier for the
                credential. Optional, defaults to None. Required for encoding
                and decoding if the attestation measurement is not provided.
        """
        super(AttestationCredential, self).__init__(tag=Tags.CREDENTIAL_VALUE)

        self._nonce = None
        self._attestation_type = None
        self._attestation_measurement = None
        self._attestation_assertion = None

        self.nonce = nonce
        self.attestation_type = attestation_type
        self.attestation_measurement = attestation_measurement
        self.attestation_assertion = attestation_assertion

    @property
    def nonce(self):
        return self._nonce

    @nonce.setter
    def nonce(self, value):
        if value is None:
            self._nonce = None
        elif isinstance(value, Nonce):
            self._nonce = value
        else:
            raise TypeError("Nonce must be a Nonce struct.")

    @property
    def attestation_type(self):
        if self._attestation_type:
            return self._attestation_type.value
        else:
            return None

    @attestation_type.setter
    def attestation_type(self, value):
        if value is None:
            self._attestation_type = None
        elif isinstance(value, enums.AttestationType):
            self._attestation_type = Enumeration(
                enums.AttestationType,
                value=value,
                tag=Tags.ATTESTATION_TYPE
            )
        else:
            raise TypeError(
                "Attestation type must be an AttestationType enumeration."
            )

    @property
    def attestation_measurement(self):
        if self._attestation_measurement:
            return self._attestation_measurement.value
        else:
            return None

    @attestation_measurement.setter
    def attestation_measurement(self, value):
        if value is None:
            self._attestation_measurement = None
        elif isinstance(value, six.binary_type):
            self._attestation_measurement = primitives.ByteString(
                value=value,
                tag=enums.Tags.ATTESTATION_MEASUREMENT
            )
        else:
            raise TypeError("Attestation measurement must be bytes.")

    @property
    def attestation_assertion(self):
        if self._attestation_assertion:
            return self._attestation_assertion.value
        else:
            return None

    @attestation_assertion.setter
    def attestation_assertion(self, value):
        if value is None:
            self._attestation_assertion = None
        elif isinstance(value, six.binary_type):
            self._attestation_assertion = primitives.ByteString(
                value=value,
                tag=enums.Tags.ATTESTATION_ASSERTION
            )
        else:
            raise TypeError("Attestation assertion must be bytes.")

    def read(self, input_stream):
        """
        Read the data encoding the AttestationCredential struct and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if either the nonce or attestation type are
                missing from the encoding. Also raised if neither the
                attestation measurement nor the attestation assertion are
                included in the encoding.

        """
        super(AttestationCredential, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.NONCE, local_stream):
            self._nonce = Nonce()
            self._nonce.read(local_stream)
        else:
            raise ValueError(
                "Attestation credential encoding is missing the nonce."
            )

        if self.is_tag_next(enums.Tags.ATTESTATION_TYPE, local_stream):
            self._attestation_type = primitives.Enumeration(
                enums.AttestationType,
                tag=enums.Tags.ATTESTATION_TYPE
            )
            self._attestation_type.read(local_stream)
        else:
            raise ValueError(
                "Attestation credential encoding is missing the attestation "
                "type."
            )

        self._attestation_measurement = None
        if self.is_tag_next(enums.Tags.ATTESTATION_MEASUREMENT, local_stream):
            self._attestation_measurement = primitives.ByteString(
                tag=enums.Tags.ATTESTATION_MEASUREMENT
            )
            self._attestation_measurement.read(local_stream)

        self._attestation_assertion = None
        if self.is_tag_next(enums.Tags.ATTESTATION_ASSERTION, local_stream):
            self._attestation_assertion = primitives.ByteString(
                tag=enums.Tags.ATTESTATION_ASSERTION
            )
            self._attestation_assertion.read(local_stream)

        if ((self._attestation_measurement is None) and
                (self._attestation_assertion is None)):
            raise ValueError(
                "Attestation credential encoding is missing either the "
                "attestation measurement or the attestation assertion."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the AttestationCredential struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if either the nonce or attestation type are
                not defined. Also raised if neither the attestation measurement
                nor the attestation assertion are defined.
        """
        local_stream = BytearrayStream()

        if self._nonce:
            self._nonce.write(local_stream)
        else:
            raise ValueError(
                "Attestation credential struct is missing the nonce."
            )

        if self._attestation_type:
            self._attestation_type.write(local_stream)
        else:
            raise ValueError(
                "Attestation credential struct is missing the attestation "
                "type."
            )

        if self._attestation_measurement:
            self._attestation_measurement.write(local_stream)
        if self._attestation_assertion:
            self._attestation_assertion.write(local_stream)

        if ((self._attestation_measurement is None) and
                (self._attestation_assertion is None)):
            raise ValueError(
                "Attestation credential struct is missing either the "
                "attestation measurement or the attestation assertion."
            )

        self.length = local_stream.length()
        super(AttestationCredential, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, AttestationCredential):
            if self.nonce != other.nonce:
                return False
            elif self.attestation_type != other.attestation_type:
                return False
            elif self.attestation_measurement != other.attestation_measurement:
                return False
            elif self.attestation_assertion != other.attestation_assertion:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, AttestationCredential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "nonce={}".format(repr(self.nonce)),
            "attestation_type={}".format(self.attestation_type),
            "attestation_measurement={}".format(self.attestation_measurement),
            "attestation_assertion={}".format(self.attestation_assertion)
        ])
        return "AttestationCredential({})".format(args)

    def __str__(self):
        return "{" \
               "'nonce': " + str(self.nonce) + ", " \
               "'attestation_type': " + str(self.attestation_type) + ", " \
               "'attestation_measurement': " + \
               str(self.attestation_measurement) + ", " \
               "'attestation_assertion': " + \
               str(self.attestation_assertion) + "}"


class Credential(primitives.Struct):
    """
    A struct representing a Credential object.

    Attributes:
        credential_type: The credential type, a CredentialType enumeration.
        credential_value: The credential value, a CredentialValue instance.
    """

    def __init__(self, credential_type=None, credential_value=None):
        """
        Construct a Credential struct.

        Args:
            credential_type (CredentialType): An enumeration value that
                specifies the type of the credential struct. Optional,
                defaults to None. Required for encoding and decoding.
            credential_value (CredentialValue): The credential value
                corresponding to the credential type. Optional, defaults to
                None. Required for encoding and decoding.
        """
        super(Credential, self).__init__(tag=Tags.CREDENTIAL)

        self._credential_type = None
        self._credential_value = None

        self.credential_type = credential_type
        self.credential_value = credential_value

    @property
    def credential_type(self):
        if self._credential_type:
            return self._credential_type.value
        else:
            return None

    @credential_type.setter
    def credential_type(self, value):
        if value is None:
            self._credential_type = None
        elif isinstance(value, enums.CredentialType):
            self._credential_type = Enumeration(
                enums.CredentialType,
                value=value,
                tag=Tags.CREDENTIAL_TYPE
            )
        else:
            raise TypeError(
                "Credential type must be a CredentialType enumeration."
            )

    @property
    def credential_value(self):
        return self._credential_value

    @credential_value.setter
    def credential_value(self, value):
        if value is None:
            self._credential_value = None
        elif isinstance(value, CredentialValue):
            self._credential_value = value
        else:
            raise TypeError(
                "Credential value must be a CredentialValue struct."
            )

    def read(self, input_stream):
        """
        Read the data encoding the Credential struct and decode it into its
        constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if either the credential type or value are
                missing from the encoding.
        """
        super(Credential, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.CREDENTIAL_TYPE, local_stream):
            self._credential_type = primitives.Enumeration(
                enum=enums.CredentialType,
                tag=enums.Tags.CREDENTIAL_TYPE
            )
            self._credential_type.read(local_stream)
        else:
            raise ValueError(
                "Credential encoding missing the credential type."
            )

        if self.is_tag_next(enums.Tags.CREDENTIAL_VALUE, local_stream):
            if self.credential_type == \
                    enums.CredentialType.USERNAME_AND_PASSWORD:
                self._credential_value = UsernamePasswordCredential()
            elif self.credential_type == enums.CredentialType.DEVICE:
                self._credential_value = DeviceCredential()
            elif self.credential_type == enums.CredentialType.ATTESTATION:
                self._credential_value = AttestationCredential()
            else:
                raise ValueError(
                    "Credential encoding includes unrecognized credential "
                    "type."
                )
            self._credential_value.read(local_stream)
        else:
            raise ValueError(
                "Credential encoding missing the credential value."
            )

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the Credential struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.

        Raises:
            ValueError: Raised if either the credential type or value are not
                defined.
        """
        local_stream = BytearrayStream()

        if self._credential_type:
            self._credential_type.write(local_stream)
        else:
            raise ValueError(
                "Credential struct missing the credential type."
            )

        if self._credential_value:
            self._credential_value.write(local_stream)
        else:
            raise ValueError(
                "Credential struct missing the credential value."
            )

        self.length = local_stream.length()
        super(Credential, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, Credential):
            if self.credential_type != other.credential_type:
                return False
            elif self.credential_value != other.credential_value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Credential):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "credential_type={}".format(self.credential_type),
            "credential_value={}".format(repr(self.credential_value))
        ])
        return "Credential({})".format(args)

    def __str__(self):
        return str({
            "credential_type": self.credential_type,
            "credential_value": str(self.credential_value)
        })


class KeyBlock(Struct):

    class KeyCompressionType(Enumeration):

        def __init__(self, value=None):
            super(KeyBlock.KeyCompressionType, self).__init__(
                enums.KeyCompressionType, value, Tags.KEY_COMPRESSION_TYPE)

    def __init__(self,
                 key_format_type=None,
                 key_compression_type=None,
                 key_value=None,
                 cryptographic_algorithm=None,
                 cryptographic_length=None,
                 key_wrapping_data=None):
        super(KeyBlock, self).__init__(Tags.KEY_BLOCK)
        self.key_format_type = key_format_type
        self.key_compression_type = key_compression_type
        self.key_value = key_value
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.key_wrapping_data = key_wrapping_data
        self.validate()

    def read(self, istream):
        super(KeyBlock, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.key_format_type = KeyFormatType()
        self.key_format_type.read(tstream)

        if self.is_tag_next(Tags.KEY_COMPRESSION_TYPE, tstream):
            self.key_compression_type = KeyBlock.KeyCompressionType()
            self.key_compression_type.read(tstream)

        self.key_value = KeyValue()
        self.key_value.read(tstream)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_ALGORITHM, tstream):
            self.cryptographic_algorithm = attributes.CryptographicAlgorithm()
            self.cryptographic_algorithm.read(tstream)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_LENGTH, tstream):
            self.cryptographic_length = attributes.CryptographicLength()
            self.cryptographic_length.read(tstream)

        if self.is_tag_next(Tags.KEY_WRAPPING_DATA, tstream):
            self.key_wrapping_data = KeyWrappingData()
            self.key_wrapping_data.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.key_format_type.write(tstream)

        if self.key_compression_type is not None:
            self.key_compression_type.write(tstream)

        self.key_value.write(tstream)

        if self.cryptographic_algorithm is not None:
            self.cryptographic_algorithm.write(tstream)
        if self.cryptographic_length is not None:
            self.cryptographic_length.write(tstream)
        if self.key_wrapping_data is not None:
            self.key_wrapping_data.write(tstream)

        # Write the length and value of the credential
        self.length = tstream.length()
        super(KeyBlock, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.key_format_type is not None:
            if type(self.key_format_type) is not KeyFormatType:
                member = 'KeyBlock.key_format_type'
                exp_type = KeyFormatType
                rcv_type = type(self.key_format_type)
                msg = exceptions.ErrorStrings.BAD_EXP_RECV.format(
                    member,
                    'type',
                    exp_type,
                    rcv_type
                )
                raise TypeError(msg)


# 2.1.4
class KeyMaterial(ByteString):

    def __init__(self, value=None):
        super(KeyMaterial, self).__init__(value, Tags.KEY_MATERIAL)


# TODO (peter-hamilton) Get rid of this and replace with a KeyMaterial factory.
class KeyMaterialStruct(Struct):

    def __init__(self):
        super(KeyMaterialStruct, self).__init__(Tags.KEY_MATERIAL)

        self.data = BytearrayStream()

        self.validate()

    def read(self, istream):
        super(KeyMaterialStruct, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.data = BytearrayStream(tstream.read())

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()
        tstream.write(self.data.buffer)

        self.length = tstream.length()
        super(KeyMaterialStruct, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # NOTE (peter-hamilton): Intentional pass, no way to validate data.
        pass


class KeyValue(Struct):

    def __init__(self,
                 key_material=None,
                 attributes=None):
        super(KeyValue, self).__init__(Tags.KEY_VALUE)

        if key_material is None:
            self.key_material = KeyMaterial()
        else:
            self.key_material = key_material

        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream):
        super(KeyValue, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # TODO (peter-hamilton) Replace this with a KeyMaterial factory.
        if self.is_type_next(Types.STRUCTURE, tstream):
            self.key_material = KeyMaterialStruct()
            self.key_material.read(tstream)
        else:
            self.key_material = KeyMaterial()
            self.key_material.read(tstream)

        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.key_material.write(tstream)

        for attribute in self.attributes:
            attribute.write(tstream)

        self.length = tstream.length()
        super(KeyValue, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Replace with check against KeyMaterial factory.
        if not isinstance(self.key_material, KeyMaterial):
            msg = "invalid key material"
            msg += "; expected {0}, received {1}".format(
                KeyMaterial, self.key_material)
            raise TypeError(msg)

        if isinstance(self.attributes, list):
            for i in xrange(len(self.attributes)):
                attribute = self.attributes[i]
                if not isinstance(attribute, Attribute):
                    msg = "invalid attribute ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        Attribute, attribute)
                    raise TypeError(msg)
        else:
            msg = "invalid attributes list"
            msg += "; expected {0}, received {1}".format(
                list, self.attributes)
            raise TypeError(msg)


class EncryptionKeyInformation(Struct):
    """
    A set of values detailing how an encrypted value was encrypted.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None):
        """
        Construct an EncryptionKeyInformation struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) used for encryption. Required for encoding
                and decoding.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the encryption process. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
        """
        super(EncryptionKeyInformation, self).__init__(
            tag=Tags.ENCRYPTION_KEY_INFORMATION
        )

        self._unique_identifier = None
        self._cryptographic_parameters = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters

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
            raise TypeError("Unique identifier must be a string.")

    @property
    def cryptographic_parameters(self):
        return self._cryptographic_parameters

    @cryptographic_parameters.setter
    def cryptographic_parameters(self, value):
        if not value:
            self._cryptographic_parameters = None
        elif isinstance(value, dict):
            self._cryptographic_parameters = CryptographicParameters(**value)
        elif isinstance(value, CryptographicParameters):
            self._cryptographic_parameters = value
        else:
            raise TypeError(
                "Cryptographic parameters must be a CryptographicParameters "
                "struct."
            )

    def read(self, input_stream):
        """
        Read the data encoding the EncryptionKeyInformation struct and decode
        it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
        """
        super(EncryptionKeyInformation, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the unique identifier attribute."
            )

        if self.is_tag_next(
                enums.Tags.CRYPTOGRAPHIC_PARAMETERS,
                local_stream
        ):
            self._cryptographic_parameters = CryptographicParameters()
            self._cryptographic_parameters.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the EncryptionKeyInformation struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
        """
        local_stream = BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the unique identifier attribute."
            )

        if self._cryptographic_parameters:
            self._cryptographic_parameters.write(local_stream)

        self.length = local_stream.length()
        super(EncryptionKeyInformation, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, EncryptionKeyInformation):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters != \
                    other.cryptographic_parameters:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, EncryptionKeyInformation):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "cryptographic_parameters={0}".format(
                repr(self.cryptographic_parameters)
            )
        ])
        return "EncryptionKeyInformation({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters
        })


class MACSignatureKeyInformation(primitives.Struct):
    """
    A set of values detailing how an MAC/signed value was MAC/signed.
    """

    def __init__(self,
                 unique_identifier=None,
                 cryptographic_parameters=None):
        """
        Construct a MACSignatureKeyInformation struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a symmetric key) used for MAC/signing. Required for encoding
                and decoding.
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the MAC/signing process. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
        """
        super(MACSignatureKeyInformation, self).__init__(
            tag=Tags.MAC_SIGNATURE_KEY_INFORMATION
        )

        self._unique_identifier = None
        self._cryptographic_parameters = None

        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters

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
            raise TypeError("Unique identifier must be a string.")

    @property
    def cryptographic_parameters(self):
        return self._cryptographic_parameters

    @cryptographic_parameters.setter
    def cryptographic_parameters(self, value):
        if not value:
            self._cryptographic_parameters = None
        elif isinstance(value, dict):
            self._cryptographic_parameters = CryptographicParameters(**value)
        elif isinstance(value, CryptographicParameters):
            self._cryptographic_parameters = value
        else:
            raise TypeError(
                "Cryptographic parameters must be a CryptographicParameters "
                "struct."
            )

    def read(self, input_stream):
        """
        Read the data encoding the MACSignatureKeyInformation struct and
        decode it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
        """
        super(MACSignatureKeyInformation, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.UNIQUE_IDENTIFIER, local_stream):
            self._unique_identifier = primitives.TextString(
                tag=enums.Tags.UNIQUE_IDENTIFIER
            )
            self._unique_identifier.read(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the unique identifier attribute."
            )

        if self.is_tag_next(
                enums.Tags.CRYPTOGRAPHIC_PARAMETERS,
                local_stream
        ):
            self._cryptographic_parameters = CryptographicParameters()
            self._cryptographic_parameters.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the MACSignatureKeyInformation struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
        """
        local_stream = BytearrayStream()

        if self._unique_identifier:
            self._unique_identifier.write(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the unique identifier attribute."
            )

        if self._cryptographic_parameters:
            self._cryptographic_parameters.write(local_stream)

        self.length = local_stream.length()
        super(MACSignatureKeyInformation, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, MACSignatureKeyInformation):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.cryptographic_parameters != \
                    other.cryptographic_parameters:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, MACSignatureKeyInformation):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "cryptographic_parameters={0}".format(
                repr(self.cryptographic_parameters)
            )
        ])
        return "MACSignatureKeyInformation({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'cryptographic_parameters': self.cryptographic_parameters
        })


class KeyWrappingData(Struct):
    """
    A set of key block values needed for key wrapping functionality
    """

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 mac_signature=None,
                 iv_counter_nonce=None,
                 encoding_option=None):
        """
        Construct a KeyWrappingData struct.

        Args:
            wrapping_method (WrappingMethod): An enumeration value that
                specifies the method to use to wrap the key value. Optional,
                defaults to None. Required for encoding and decoding.
            encryption_key_information (EncryptionKeyInformation): A struct
                containing the unique identifier of the encryption key and
                associated cryptographic parameters. Optional, defaults to
                None.
            mac_signature_key_information (MACSignatureKeyInformation): A
                struct containing the unique identifier of the MAC/signature
                key and associated cryptographic parameters. Optional,
                defaults to None.
            mac_signature (bytes): Bytes containing a MAC or signature of the
                key value. Optional, defaults to None.
            iv_counter_nonce (bytes): Bytes containing an IV/counter/nonce
                value if it is required by the wrapping method. Optional,
                defaults to None.
            encoding_option (EncodingOption): An enumeration value that
                specifies the encoding of the key value before it is wrapped.
                Optional, defaults to None.
        """
        super(KeyWrappingData, self).__init__(Tags.KEY_WRAPPING_DATA)

        self._wrapping_method = None
        self._encryption_key_information = None
        self._mac_signature_key_information = None
        self._mac_signature = None
        self._iv_counter_nonce = None
        self._encoding_option = None

        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.mac_signature = mac_signature
        self.iv_counter_nonce = iv_counter_nonce
        self.encoding_option = encoding_option

    @property
    def wrapping_method(self):
        if self._wrapping_method:
            return self._wrapping_method.value
        else:
            return None

    @wrapping_method.setter
    def wrapping_method(self, value):
        if value is None:
            self._wrapping_method = None
        elif isinstance(value, enums.WrappingMethod):
            self._wrapping_method = Enumeration(
                enums.WrappingMethod,
                value=value,
                tag=Tags.WRAPPING_METHOD
            )
        else:
            raise TypeError(
                "Wrapping method must be a WrappingMethod enumeration."
            )

    @property
    def encryption_key_information(self):
        return self._encryption_key_information

    @encryption_key_information.setter
    def encryption_key_information(self, value):
        if not value:
            self._encryption_key_information = None
        elif isinstance(value, dict):
            self._encryption_key_information = \
                EncryptionKeyInformation(**value)
        elif isinstance(value, EncryptionKeyInformation):
            self._encryption_key_information = value
        else:
            raise TypeError(
                "Encryption key information must be an "
                "EncryptionKeyInformation struct."
            )

    @property
    def mac_signature_key_information(self):
        return self._mac_signature_key_information

    @mac_signature_key_information.setter
    def mac_signature_key_information(self, value):
        if not value:
            self._mac_signature_key_information = None
        elif isinstance(value, dict):
            self._mac_signature_key_information = \
                MACSignatureKeyInformation(**value)
        elif isinstance(value, MACSignatureKeyInformation):
            self._mac_signature_key_information = value
        else:
            raise TypeError(
                "MAC/signature key information must be an "
                "MACSignatureKeyInformation struct."
            )

    @property
    def mac_signature(self):
        if self._mac_signature:
            return self._mac_signature.value
        else:
            return None

    @mac_signature.setter
    def mac_signature(self, value):
        if value is None:
            self._mac_signature = None
        elif isinstance(value, six.binary_type):
            self._mac_signature = primitives.ByteString(
                value=value,
                tag=enums.Tags.MAC_SIGNATURE
            )
        else:
            raise TypeError("MAC/signature must be bytes.")

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
            raise TypeError("IV/counter/nonce must be bytes.")

    @property
    def encoding_option(self):
        if self._encoding_option:
            return self._encoding_option.value
        else:
            return None

    @encoding_option.setter
    def encoding_option(self, value):
        if value is None:
            self._encoding_option = None
        elif isinstance(value, enums.EncodingOption):
            self._encoding_option = Enumeration(
                enums.EncodingOption,
                value=value,
                tag=Tags.ENCODING_OPTION
            )
        else:
            raise TypeError(
                "Encoding option must be an EncodingOption enumeration."
            )

    def read(self, input_stream):
        """
        Read the data encoding the KeyWrappingData struct and decode it into
        its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
        """
        super(KeyWrappingData, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.WRAPPING_METHOD, local_stream):
            self._wrapping_method = primitives.Enumeration(
                enum=enums.WrappingMethod,
                tag=enums.Tags.WRAPPING_METHOD
            )
            self._wrapping_method.read(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self.is_tag_next(
                enums.Tags.ENCRYPTION_KEY_INFORMATION,
                local_stream
        ):
            self._encryption_key_information = EncryptionKeyInformation()
            self._encryption_key_information.read(local_stream)
        if self.is_tag_next(
                enums.Tags.MAC_SIGNATURE_KEY_INFORMATION,
                local_stream
        ):
            self._mac_signature_key_information = MACSignatureKeyInformation()
            self._mac_signature_key_information.read(local_stream)

        if self.is_tag_next(enums.Tags.MAC_SIGNATURE, local_stream):
            self._mac_signature = primitives.ByteString(
                tag=enums.Tags.MAC_SIGNATURE
            )
            self._mac_signature.read(local_stream)

        if self.is_tag_next(enums.Tags.IV_COUNTER_NONCE, local_stream):
            self._iv_counter_nonce = primitives.ByteString(
                tag=enums.Tags.IV_COUNTER_NONCE
            )
            self._iv_counter_nonce.read(local_stream)

        if self.is_tag_next(enums.Tags.ENCODING_OPTION, local_stream):
            self._encoding_option = primitives.Enumeration(
                enum=enums.EncodingOption,
                tag=enums.Tags.ENCODING_OPTION
            )
            self._encoding_option.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the KeyWrappingData struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
        """
        local_stream = BytearrayStream()

        if self._wrapping_method:
            self._wrapping_method.write(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self._encryption_key_information:
            self._encryption_key_information.write(local_stream)
        if self._mac_signature_key_information:
            self._mac_signature_key_information.write(local_stream)
        if self._mac_signature:
            self._mac_signature.write(local_stream)
        if self._iv_counter_nonce:
            self._iv_counter_nonce.write(local_stream)
        if self._encoding_option:
            self._encoding_option.write(local_stream)

        self.length = local_stream.length()
        super(KeyWrappingData, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, KeyWrappingData):
            if self.wrapping_method != other.wrapping_method:
                return False
            elif self.encryption_key_information != \
                    other.encryption_key_information:
                return False
            elif self.mac_signature_key_information != \
                    other.mac_signature_key_information:
                return False
            elif self.mac_signature != other.mac_signature:
                return False
            elif self.iv_counter_nonce != other.iv_counter_nonce:
                return False
            elif self.encoding_option != other.encoding_option:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, KeyWrappingData):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "wrapping_method={0}".format(self.wrapping_method),
            "encryption_key_information={0}".format(
                repr(self.encryption_key_information)
            ),
            "mac_signature_key_information={0}".format(
                repr(self.mac_signature_key_information)
            ),
            "mac_signature={0}".format(self.mac_signature),
            "iv_counter_nonce={0}".format(self.iv_counter_nonce),
            "encoding_option={0}".format(self.encoding_option)
        ])
        return "KeyWrappingData({0})".format(args)

    def __str__(self):
        return str({
            'wrapping_method': self.wrapping_method,
            'encryption_key_information': self.encryption_key_information,
            'mac_signature_key_information':
                self.mac_signature_key_information,
            'mac_signature': self.mac_signature,
            'iv_counter_nonce': self.iv_counter_nonce,
            'encoding_option': self.encoding_option
        })


class KeyWrappingSpecification(primitives.Struct):
    """
    A set of values needed for key wrapping functionality.
    """

    def __init__(self,
                 wrapping_method=None,
                 encryption_key_information=None,
                 mac_signature_key_information=None,
                 attribute_names=None,
                 encoding_option=None):
        """
        Construct a KeyWrappingSpecification struct.

        Args:
            wrapping_method (WrappingMethod): An enumeration value that
                specifies the method to use to wrap the key value. Optional,
                defaults to None. Required for encoding and decoding.
            encryption_key_information (EncryptionKeyInformation): A struct
                containing the unique identifier of the encryption key and
                associated cryptographic parameters. Optional, defaults to
                None.
            mac_signature_key_information (MACSignatureKeyInformation): A
                struct containing the unique identifier of the MAC/signature
                key and associated cryptographic parameters. Optional,
                defaults to None.
            attribute_names (list): A list of strings representing the names
                of attributes that should be wrapped with the key material.
                Optional, defaults to None.
            encoding_option (EncodingOption): An enumeration value that
                specifies the encoding of the key value before it is wrapped.
                Optional, defaults to None.
        """
        super(KeyWrappingSpecification, self).__init__(
            tag=Tags.KEY_WRAPPING_SPECIFICATION
        )

        self._wrapping_method = None
        self._encryption_key_information = None
        self._mac_signature_key_information = None
        self._attribute_names = None
        self._encoding_option = None

        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.attribute_names = attribute_names
        self.encoding_option = encoding_option

    @property
    def wrapping_method(self):
        if self._wrapping_method:
            return self._wrapping_method.value
        else:
            return None

    @wrapping_method.setter
    def wrapping_method(self, value):
        if value is None:
            self._wrapping_method = None
        elif isinstance(value, enums.WrappingMethod):
            self._wrapping_method = Enumeration(
                enums.WrappingMethod,
                value=value,
                tag=Tags.WRAPPING_METHOD
            )
        else:
            raise TypeError(
                "Wrapping method must be a WrappingMethod enumeration."
            )

    @property
    def encryption_key_information(self):
        return self._encryption_key_information

    @encryption_key_information.setter
    def encryption_key_information(self, value):
        if value is None:
            self._encryption_key_information = None
        elif isinstance(value, EncryptionKeyInformation):
            self._encryption_key_information = value
        else:
            raise TypeError(
                "Encryption key information must be an "
                "EncryptionKeyInformation struct."
            )

    @property
    def mac_signature_key_information(self):
        return self._mac_signature_key_information

    @mac_signature_key_information.setter
    def mac_signature_key_information(self, value):
        if value is None:
            self._mac_signature_key_information = None
        elif isinstance(value, MACSignatureKeyInformation):
            self._mac_signature_key_information = value
        else:
            raise TypeError(
                "MAC/signature key information must be an "
                "MACSignatureKeyInformation struct."
            )

    @property
    def attribute_names(self):
        if self._attribute_names:
            attribute_names = []
            for i in self._attribute_names:
                attribute_names.append(i.value)
            return attribute_names
        else:
            return None

    @attribute_names.setter
    def attribute_names(self, value):
        if value is None:
            self._attribute_names = None
        elif isinstance(value, list):
            attribute_names = []
            for i in value:
                if isinstance(i, six.string_types):
                    attribute_names.append(
                        primitives.TextString(
                            value=i,
                            tag=enums.Tags.ATTRIBUTE_NAME
                        )
                    )
                else:
                    raise TypeError(
                        "Attribute names must be a list of strings."
                    )
            self._attribute_names = attribute_names
        else:
            raise TypeError("Attribute names must be a list of strings.")

    @property
    def encoding_option(self):
        if self._encoding_option:
            return self._encoding_option.value
        else:
            return None

    @encoding_option.setter
    def encoding_option(self, value):
        if value is None:
            self._encoding_option = None
        elif isinstance(value, enums.EncodingOption):
            self._encoding_option = Enumeration(
                enums.EncodingOption,
                value=value,
                tag=Tags.ENCODING_OPTION
            )
        else:
            raise TypeError(
                "Encoding option must be an EncodingOption enumeration."
            )

    def read(self, input_stream):
        """
        Read the data encoding the KeyWrappingSpecification struct and decode
        it into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
        """
        super(KeyWrappingSpecification, self).read(input_stream)
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(enums.Tags.WRAPPING_METHOD, local_stream):
            self._wrapping_method = primitives.Enumeration(
                enum=enums.WrappingMethod,
                tag=enums.Tags.WRAPPING_METHOD
            )
            self._wrapping_method.read(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self.is_tag_next(
                enums.Tags.ENCRYPTION_KEY_INFORMATION,
                local_stream
        ):
            self._encryption_key_information = EncryptionKeyInformation()
            self._encryption_key_information.read(local_stream)
        if self.is_tag_next(
                enums.Tags.MAC_SIGNATURE_KEY_INFORMATION,
                local_stream
        ):
            self._mac_signature_key_information = MACSignatureKeyInformation()
            self._mac_signature_key_information.read(local_stream)

        attribute_names = []
        while self.is_tag_next(enums.Tags.ATTRIBUTE_NAME, local_stream):
            attribute_name = primitives.TextString(
                tag=enums.Tags.ATTRIBUTE_NAME
            )
            attribute_name.read(local_stream)
            attribute_names.append(attribute_name)
        self._attribute_names = attribute_names

        if self.is_tag_next(enums.Tags.ENCODING_OPTION, local_stream):
            self._encoding_option = primitives.Enumeration(
                enum=enums.EncodingOption,
                tag=enums.Tags.ENCODING_OPTION
            )
            self._encoding_option.read(local_stream)

        self.is_oversized(local_stream)

    def write(self, output_stream):
        """
        Write the data encoding the KeyWrappingSpecification struct to a
        stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
        """
        local_stream = BytearrayStream()

        if self._wrapping_method:
            self._wrapping_method.write(local_stream)
        else:
            raise ValueError(
                "Invalid struct missing the wrapping method attribute."
            )

        if self._encryption_key_information:
            self._encryption_key_information.write(local_stream)
        if self._mac_signature_key_information:
            self._mac_signature_key_information.write(local_stream)
        if self._attribute_names:
            for unique_identifier in self._attribute_names:
                unique_identifier.write(local_stream)
        if self._encoding_option:
            self._encoding_option.write(local_stream)

        self.length = local_stream.length()
        super(KeyWrappingSpecification, self).write(output_stream)
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, KeyWrappingSpecification):
            if self.wrapping_method != other.wrapping_method:
                return False
            elif self.encryption_key_information != \
                    other.encryption_key_information:
                return False
            elif self.mac_signature_key_information != \
                    other.mac_signature_key_information:
                return False
            elif self.attribute_names != other.attribute_names:
                return False
            elif self.encoding_option != other.encoding_option:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, KeyWrappingSpecification):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "wrapping_method={0}".format(self.wrapping_method),
            "encryption_key_information={0}".format(
                repr(self.encryption_key_information)
            ),
            "mac_signature_key_information={0}".format(
                repr(self.mac_signature_key_information)
            ),
            "attribute_names={0}".format(self.attribute_names),
            "encoding_option={0}".format(self.encoding_option)
        ])
        return "KeyWrappingSpecification({0})".format(args)

    def __str__(self):
        return str({
            'wrapping_method': self.wrapping_method,
            'encryption_key_information': self.encryption_key_information,
            'mac_signature_key_information':
                self.mac_signature_key_information,
            'attribute_names': self.attribute_names,
            'encoding_option': self.encoding_option
        })


class TemplateAttribute(Struct):

    def __init__(self,
                 names=None,
                 attributes=None,
                 tag=Tags.TEMPLATE_ATTRIBUTE):
        super(TemplateAttribute, self).__init__(tag)

        if names is None:
            self.names = list()
        else:
            self.names = names

        if attributes is None:
            self.attributes = list()
        else:
            self.attributes = attributes

        self.validate()

    def read(self, istream):
        super(TemplateAttribute, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.names = list()
        self.attributes = list()

        # Read the names of the template attribute, 0 or more
        while self.is_tag_next(Tags.NAME, tstream):
            name = attributes.Name()
            name.read(tstream)
            self.names.append(name)

        # Read the attributes of the template attribute, 0 or more
        while self.is_tag_next(Tags.ATTRIBUTE, tstream):
            attribute = Attribute()
            attribute.read(tstream)
            self.attributes.append(attribute)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the names and attributes of the template attribute
        for name in self.names:
            name.write(tstream)
        for attribute in self.attributes:
            attribute.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(TemplateAttribute, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass

    def __eq__(self, other):
        if isinstance(other, TemplateAttribute):
            if len(self.names) != len(other.names):
                return False
            if len(self.attributes) != len(other.attributes):
                return False

            # TODO (peter-hamilton) Allow order independence?

            for i in xrange(len(self.names)):
                a = self.names[i]
                b = other.names[i]

                if a != b:
                    return False

            for i in xrange(len(self.attributes)):
                a = self.attributes[i]
                b = other.attributes[i]

                if a != b:
                    return False

            return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, TemplateAttribute):
            return not (self == other)
        else:
            return NotImplemented


class CommonTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(CommonTemplateAttribute, self).__init__(
            names, attributes, Tags.COMMON_TEMPLATE_ATTRIBUTE)


class PrivateKeyTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(PrivateKeyTemplateAttribute, self).__init__(
            names, attributes, Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE)


class PublicKeyTemplateAttribute(TemplateAttribute):

    def __init__(self,
                 names=None,
                 attributes=None):
        super(PublicKeyTemplateAttribute, self).__init__(
            names, attributes, Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE)


# 2.1.9
class ExtensionName(TextString):
    """
    The name of an extended Object.

    A part of ExtensionInformation, specifically identifying an Object that is
    a custom vendor addition to the KMIP specification. See Section 2.1.9 of
    the KMIP 1.1 specification for more information.

    Attributes:
        value: The string data representing the extension name.
    """
    def __init__(self, value=''):
        """
        Construct an ExtensionName object.

        Args:
            value (str): The string data representing the extension name.
                Optional, defaults to the empty string.
        """
        super(ExtensionName, self).__init__(value, Tags.EXTENSION_NAME)


class ExtensionTag(Integer):
    """
    The tag of an extended Object.

    A part of ExtensionInformation. See Section 2.1.9 of the KMIP 1.1
    specification for more information.

    Attributes:
        value: The tag number identifying the extended object.
    """
    def __init__(self, value=0):
        """
        Construct an ExtensionTag object.

        Args:
            value (int): A number representing the extension tag. Often
                displayed in hex format. Optional, defaults to 0.
        """
        super(ExtensionTag, self).__init__(value, Tags.EXTENSION_TAG)


class ExtensionType(Integer):
    """
    The type of an extended Object.

    A part of ExtensionInformation, specifically identifying the type of the
    Object in the specification extension. See Section 2.1.9 of the KMIP 1.1
    specification for more information.

    Attributes:
        value: The type enumeration for the extended object.
    """
    def __init__(self, value=None):
        """
        Construct an ExtensionType object.

        Args:
            value (Types): A number representing a Types enumeration value,
                indicating the type of the extended Object. Optional, defaults
                to None.
        """
        super(ExtensionType, self).__init__(value, Tags.EXTENSION_TYPE)


class ExtensionInformation(Struct):
    """
    A structure describing Objects defined in KMIP specification extensions.

    It is used specifically for Objects with Item Tag values in the Extensions
    range and appears in responses to Query requests for server extension
    information. See Sections 2.1.9 and 4.25 of the KMIP 1.1 specification for
    more information.

    Attributes:
        extension_name: The name of the extended Object.
        extension_tag: The tag of the extended Object.
        extension_type: The type of the extended Object.
    """
    def __init__(self, extension_name=None, extension_tag=None,
                 extension_type=None):
        """
        Construct an ExtensionInformation object.

        Args:
            extension_name (ExtensionName): The name of the extended Object.
            extension_tag (ExtensionTag): The tag of the extended Object.
            extension_type (ExtensionType): The type of the extended Object.
        """
        super(ExtensionInformation, self).__init__(Tags.EXTENSION_INFORMATION)

        if extension_name is None:
            self.extension_name = ExtensionName()
        else:
            self.extension_name = extension_name

        self.extension_tag = extension_tag
        self.extension_type = extension_type

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the ExtensionInformation object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(ExtensionInformation, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.extension_name.read(tstream)

        if self.is_tag_next(Tags.EXTENSION_TAG, tstream):
            self.extension_tag = ExtensionTag()
            self.extension_tag.read(tstream)
        if self.is_tag_next(Tags.EXTENSION_TYPE, tstream):
            self.extension_type = ExtensionType()
            self.extension_type.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the ExtensionInformation object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        self.extension_name.write(tstream)

        if self.extension_tag is not None:
            self.extension_tag.write(tstream)
        if self.extension_type is not None:
            self.extension_type.write(tstream)

        self.length = tstream.length()
        super(ExtensionInformation, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the ExtensionInformation object.
        """
        self.__validate()

    def __validate(self):
        if not isinstance(self.extension_name, ExtensionName):
            msg = "invalid extension name"
            msg += "; expected {0}, received {1}".format(
                ExtensionName, self.extension_name)
            raise TypeError(msg)

        if self.extension_tag is not None:
            if not isinstance(self.extension_tag, ExtensionTag):
                msg = "invalid extension tag"
                msg += "; expected {0}, received {1}".format(
                    ExtensionTag, self.extension_tag)
                raise TypeError(msg)

        if self.extension_type is not None:
            if not isinstance(self.extension_type, ExtensionType):
                msg = "invalid extension type"
                msg += "; expected {0}, received {1}".format(
                    ExtensionType, self.extension_type)
                raise TypeError(msg)

    def __eq__(self, other):
        if isinstance(other, ExtensionInformation):
            if self.extension_name != other.extension_name:
                return False
            elif self.extension_tag != other.extension_tag:
                return False
            elif self.extension_type != other.extension_type:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ExtensionInformation):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        name = "extension_name={0}".format(repr(self.extension_name))
        tag = "extension_tag={0}".format(repr(self.extension_tag))
        typ = "extension_type={0}".format(repr(self.extension_type))
        return "ExtensionInformation({0}, {1}, {2})".format(name, tag, typ)

    def __str__(self):
        return repr(self)

    @classmethod
    def create(cls, extension_name=None, extension_tag=None,
               extension_type=None):
        """
        Construct an ExtensionInformation object from provided extension
        values.

        Args:
            extension_name (str): The name of the extension. Optional,
                defaults to None.
            extension_tag (int): The tag number of the extension. Optional,
                defaults to None.
            extension_type (int): The type index of the extension. Optional,
                defaults to None.

        Returns:
            ExtensionInformation: The newly created set of extension
                information.

        Example:
            >>> x = ExtensionInformation.create('extension', 1, 1)
            >>> x.extension_name.value
            ExtensionName(value='extension')
            >>> x.extension_tag.value
            ExtensionTag(value=1)
            >>> x.extension_type.value
            ExtensionType(value=1)
        """
        extension_name = ExtensionName(extension_name)
        extension_tag = ExtensionTag(extension_tag)
        extension_type = ExtensionType(extension_type)

        return ExtensionInformation(
            extension_name=extension_name,
            extension_tag=extension_tag,
            extension_type=extension_type)


# 2.1.10
class Data(ByteString):

    def __init__(self, value=None):
        super(Data, self).__init__(value, Tags.DATA)


# 2.1.13
class MACData(ByteString):

    def __init__(self, value=None):
        super(MACData, self).__init__(value, Tags.MAC_DATA)


# 3.31, 9.1.3.2.19
class RevocationReasonCode(Enumeration):

    def __init__(self, value=RevocationReasonCodeEnum.UNSPECIFIED):
        super(RevocationReasonCode, self).__init__(
            RevocationReasonCodeEnum, value=value,
            tag=Tags.REVOCATION_REASON_CODE)


# 3.31
class RevocationReason(Struct):
    """
    A structure describing  the reason for a revocation operation.

    See Sections 2.1.9 and 4.25 of the KMIP 1.1 specification for
    more information.

    Attributes:
        code: The revocation reason code enumeration
        message: An optional revocation message
    """

    def __init__(self, code=None, message=None):
        """
        Construct a RevocationReason object.

        Parameters:
            code(RevocationReasonCode): revocation reason code
            message(string): An optional revocation message
        """
        super(RevocationReason, self).__init__(tag=Tags.REVOCATION_REASON)
        if code is not None:
            self.revocation_code = RevocationReasonCode(value=code)
        else:
            self.revocation_code = RevocationReasonCode()

        if message is not None:
            self.revocation_message = TextString(
                value=message,
                tag=Tags.REVOCATION_MESSAGE)
        else:
            self.revocation_message = None

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the RevocationReason object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(RevocationReason, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.revocation_code = RevocationReasonCode()
        self.revocation_code.read(tstream)

        if self.is_tag_next(Tags.REVOCATION_MESSAGE, tstream):
            self.revocation_message = TextString()
            self.revocation_message.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the RevocationReason object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        self.revocation_code.write(tstream)
        if self.revocation_message is not None:
            self.revocation_message.write(tstream)

        # Write the length and value
        self.length = tstream.length()
        super(RevocationReason, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        validate the RevocationReason object
        """
        if not isinstance(self.revocation_code, RevocationReasonCode):
            msg = "RevocationReaonCode expected"
            raise TypeError(msg)
        if self.revocation_message is not None:
            if not isinstance(self.revocation_message, TextString):
                msg = "TextString expect"
                raise TypeError(msg)
