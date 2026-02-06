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

from kmip import enums
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages.payloads import base

class CheckRequestPayload(base.RequestPayload):
    """
    A request payload for the Check operation.

    Attributes:
        unique_identifier: The unique ID of the object to be checked.
        usage_limits_count: The number of usage limits units that should be
            available on the checked object.
        cryptographic_usage_mask: The numeric representation of a set of usage
            masks that should be set on the checked object.
        lease_time: The date in seconds since the epoch that a lease should be
            available for on the checked object.
    """

    def __init__(self,
                 unique_identifier=None,
                 usage_limits_count=None,
                 cryptographic_usage_mask=None,
                 lease_time=None):
        """
        Construct a Check request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) to be checked. Optional, defaults to None.
            usage_limits_count (int): The number of usage limits units that
                should be available on the checked object. Optional, defaults
                to None.
            cryptographic_usage_mask (int): The numeric representation of a
                set of usage masks that should be set on the checked object.
                Optional, defaults to None.
            lease_time (int): The date in seconds since the epoch that a
                lease should be available for on the checked object. Optional,
                defaults to None.
        """
        super(CheckRequestPayload, self).__init__()

        self._unique_identifier = None
        self._usage_limits_count = None
        self._cryptographic_usage_mask = None
        self._lease_time = None

        self.unique_identifier = unique_identifier
        self.usage_limits_count = usage_limits_count
        self.cryptographic_usage_mask = cryptographic_usage_mask
        self.lease_time = lease_time

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
    def usage_limits_count(self):
        if self._usage_limits_count:
            return self._usage_limits_count.value
        else:
            return None

    @usage_limits_count.setter
    def usage_limits_count(self, value):
        if value is None:
            self._usage_limits_count = None
        elif isinstance(value, int):
            self._usage_limits_count = primitives.LongInteger(
                value=value,
                tag=enums.Tags.USAGE_LIMITS_COUNT
            )
        else:
            raise TypeError("Usage limits count must be an integer.")

    @property
    def cryptographic_usage_mask(self):
        if self._cryptographic_usage_mask:
            return self._cryptographic_usage_mask.value
        else:
            return None

    @cryptographic_usage_mask.setter
    def cryptographic_usage_mask(self, value):
        if value is None:
            self._cryptographic_usage_mask = None
        elif isinstance(value, int):
            self._cryptographic_usage_mask = primitives.Integer(
                value=value,
                tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
            )
        else:
            raise TypeError("Cryptographic usage mask must be an integer.")

    @property
    def lease_time(self):
        if self._lease_time:
            return self._lease_time.value
        else:
            return None

    @lease_time.setter
    def lease_time(self, value):
        if value is None:
            self._lease_time = None
        elif isinstance(value, int):
            self._lease_time = primitives.Interval(
                value=value,
                tag=enums.Tags.LEASE_TIME
            )
        else:
            raise TypeError("Lease time must be an integer.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Check request payload and decode it into
        its constituent parts.

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
        super(CheckRequestPayload, self).read(
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
        if self.is_tag_next(enums.Tags.USAGE_LIMITS_COUNT, local_stream):
            self._usage_limits_count = primitives.LongInteger(
                tag=enums.Tags.USAGE_LIMITS_COUNT
            )
            self._usage_limits_count.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(enums.Tags.CRYPTOGRAPHIC_USAGE_MASK, local_stream):
            self._cryptographic_usage_mask = primitives.Integer(
                tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
            )
            self._cryptographic_usage_mask.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(enums.Tags.LEASE_TIME, local_stream):
            self._lease_time = primitives.Interval(
                tag=enums.Tags.LEASE_TIME
            )
            self._lease_time.read(local_stream, kmip_version=kmip_version)

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Check request payload to a stream.

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
        if self._usage_limits_count:
            self._usage_limits_count.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._cryptographic_usage_mask:
            self._cryptographic_usage_mask.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._lease_time:
            self._lease_time.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(CheckRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, CheckRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.usage_limits_count != other.usage_limits_count:
                return False
            elif self.cryptographic_usage_mask != \
                    other.cryptographic_usage_mask:
                return False
            elif self.lease_time != other.lease_time:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CheckRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "usage_limits_count={0}".format(self.usage_limits_count),
            "cryptographic_usage_mask={0}".format(
                self.cryptographic_usage_mask
            ),
            "lease_time={0}".format(self.lease_time)
        ])
        return "CheckRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'usage_limits_count': self.usage_limits_count,
            'cryptographic_usage_mask': self.cryptographic_usage_mask,
            'lease_time': self.lease_time
        })

class CheckResponsePayload(base.ResponsePayload):
    """
    A response payload for the Check operation.

    Attributes:
        unique_identifier: The unique ID of the object that was checked.
        usage_limits_count: The number of usage limits units that should be
            available on the checked object.
        cryptographic_usage_mask: The numeric representation of a set of usage
            masks that should be set on the checked object.
        lease_time: The date in seconds since the epoch that a lease should be
            available for on the checked object.
    """

    def __init__(self,
                 unique_identifier=None,
                 usage_limits_count=None,
                 cryptographic_usage_mask=None,
                 lease_time=None):
        """
        Construct a Check response payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) that was checked. Optional, defaults to None.
            usage_limits_count (int): The number of usage limits units that
                should be available on the checked object. Optional, defaults
                to None.
            cryptographic_usage_mask (int): The numeric representation of a
                set of usage masks that should be set on the checked object.
                Optional, defaults to None.
            lease_time (int): The date in seconds since the epoch that a
                lease should be available for on the checked object. Optional,
                defaults to None.
        """
        super(CheckResponsePayload, self).__init__()

        self._unique_identifier = None
        self._usage_limits_count = None
        self._cryptographic_usage_mask = None
        self._lease_time = None

        self.unique_identifier = unique_identifier
        self.usage_limits_count = usage_limits_count
        self.cryptographic_usage_mask = cryptographic_usage_mask
        self.lease_time = lease_time

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
    def usage_limits_count(self):
        if self._usage_limits_count:
            return self._usage_limits_count.value
        else:
            return None

    @usage_limits_count.setter
    def usage_limits_count(self, value):
        if value is None:
            self._usage_limits_count = None
        elif isinstance(value, int):
            self._usage_limits_count = primitives.LongInteger(
                value=value,
                tag=enums.Tags.USAGE_LIMITS_COUNT
            )
        else:
            raise TypeError("Usage limits count must be an integer.")

    @property
    def cryptographic_usage_mask(self):
        if self._cryptographic_usage_mask:
            return self._cryptographic_usage_mask.value
        else:
            return None

    @cryptographic_usage_mask.setter
    def cryptographic_usage_mask(self, value):
        if value is None:
            self._cryptographic_usage_mask = None
        elif isinstance(value, int):
            self._cryptographic_usage_mask = primitives.Integer(
                value=value,
                tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
            )
        else:
            raise TypeError("Cryptographic usage mask must be an integer.")

    @property
    def lease_time(self):
        if self._lease_time:
            return self._lease_time.value
        else:
            return None

    @lease_time.setter
    def lease_time(self, value):
        if value is None:
            self._lease_time = None
        elif isinstance(value, int):
            self._lease_time = primitives.Interval(
                value=value,
                tag=enums.Tags.LEASE_TIME
            )
        else:
            raise TypeError("Lease time must be an integer.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Check response payload and decode it into
        its constituent parts.

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
        super(CheckResponsePayload, self).read(
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
        if self.is_tag_next(enums.Tags.USAGE_LIMITS_COUNT, local_stream):
            self._usage_limits_count = primitives.LongInteger(
                tag=enums.Tags.USAGE_LIMITS_COUNT
            )
            self._usage_limits_count.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(enums.Tags.CRYPTOGRAPHIC_USAGE_MASK, local_stream):
            self._cryptographic_usage_mask = primitives.Integer(
                tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
            )
            self._cryptographic_usage_mask.read(
                local_stream,
                kmip_version=kmip_version
            )
        if self.is_tag_next(enums.Tags.LEASE_TIME, local_stream):
            self._lease_time = primitives.Interval(
                tag=enums.Tags.LEASE_TIME
            )
            self._lease_time.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Check response payload to a stream.

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
        if self._usage_limits_count:
            self._usage_limits_count.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._cryptographic_usage_mask:
            self._cryptographic_usage_mask.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._lease_time:
            self._lease_time.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(CheckResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, CheckResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.usage_limits_count != other.usage_limits_count:
                return False
            elif self.cryptographic_usage_mask != \
                    other.cryptographic_usage_mask:
                return False
            elif self.lease_time != other.lease_time:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, CheckResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "usage_limits_count={0}".format(self.usage_limits_count),
            "cryptographic_usage_mask={0}".format(
                self.cryptographic_usage_mask
            ),
            "lease_time={0}".format(self.lease_time)
        ])
        return "CheckResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'usage_limits_count': self.usage_limits_count,
            'cryptographic_usage_mask': self.cryptographic_usage_mask,
            'lease_time': self.lease_time
        })
