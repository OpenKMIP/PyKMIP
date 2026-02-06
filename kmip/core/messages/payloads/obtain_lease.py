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

class ObtainLeaseRequestPayload(base.RequestPayload):
    """
    A request payload for the ObtainLease operation.

    Attributes:
        unique_identifier: The unique ID of the object to be leased.
    """

    def __init__(self, unique_identifier=None):
        """
        Construct an ObtainLease request payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) to obtain a lease for. Optional, defaults to
                None.
        """
        super(ObtainLeaseRequestPayload, self).__init__()

        self._unique_identifier = None
        self.unique_identifier = unique_identifier

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

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the ObtainLease request payload and decode it
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
        super(ObtainLeaseRequestPayload, self).read(
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

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the ObtainLease request payload to a stream.

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

        self.length = local_stream.length()
        super(ObtainLeaseRequestPayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, ObtainLeaseRequestPayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ObtainLeaseRequestPayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = "unique_identifier='{0}'".format(self.unique_identifier)
        return "ObtainLeaseRequestPayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier
        })

class ObtainLeaseResponsePayload(base.ResponsePayload):
    """
    A response payload for the ObtainLease operation.

    Attributes:
        unique_identifier: The unique ID of the object that was leased.
        lease_time: The amount of time, in seconds, that the object lease is
            in effect.
        last_change_date: The date, in seconds since the epoch, representing
            the last time a change was made to the object or one of its
            attributes.
    """

    def __init__(self,
                 unique_identifier=None,
                 lease_time=None,
                 last_change_date=None):
        """
        Construct an ObtainLease response payload struct.

        Args:
            unique_identifier (string): The ID of the managed object (e.g.,
                a public key) a lease was obtained for. Optional, defaults to
                None.
            lease_time (int): The amount of time, in seconds, that the object
                lease is in effect for. Optional, defaults to None.
            last_change_date (int): The date, in seconds since the epoch,
                when the last change was made to the object or one of its
                attributes. Optional, defaults to None.
        """
        super(ObtainLeaseResponsePayload, self).__init__()

        self._unique_identifier = None
        self._lease_time = None
        self._last_change_date = None

        self.unique_identifier = unique_identifier
        self.lease_time = lease_time
        self.last_change_date = last_change_date

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

    @property
    def last_change_date(self):
        if self._last_change_date:
            return self._last_change_date.value
        else:
            return None

    @last_change_date.setter
    def last_change_date(self, value):
        if value is None:
            self._last_change_date = None
        elif isinstance(value, int):
            self._last_change_date = primitives.DateTime(
                value=value,
                tag=enums.Tags.LAST_CHANGE_DATE
            )
        else:
            raise TypeError("Last change date must be an integer.")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the ObtainLease response payload and decode it
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
        super(ObtainLeaseResponsePayload, self).read(
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
        if self.is_tag_next(enums.Tags.LEASE_TIME, local_stream):
            self._lease_time = primitives.Interval(
                tag=enums.Tags.LEASE_TIME
            )
            self._lease_time.read(local_stream, kmip_version=kmip_version)
        if self.is_tag_next(enums.Tags.LAST_CHANGE_DATE, local_stream):
            self._last_change_date = primitives.DateTime(
                tag=enums.Tags.LAST_CHANGE_DATE
            )
            self._last_change_date.read(
                local_stream,
                kmip_version=kmip_version
            )

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the ObtainLease response payload to a stream.

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
        if self._lease_time:
            self._lease_time.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._last_change_date:
            self._last_change_date.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(ObtainLeaseResponsePayload, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, ObtainLeaseResponsePayload):
            if self.unique_identifier != other.unique_identifier:
                return False
            elif self.lease_time != other.lease_time:
                return False
            elif self.last_change_date != other.last_change_date:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ObtainLeaseResponsePayload):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "unique_identifier='{0}'".format(self.unique_identifier),
            "lease_time={0}".format(self.lease_time),
            "last_change_date={0}".format(self.last_change_date)
        ])
        return "ObtainLeaseResponsePayload({0})".format(args)

    def __str__(self):
        return str({
            'unique_identifier': self.unique_identifier,
            'lease_time': self.lease_time,
            'last_change_date': self.last_change_date
        })
