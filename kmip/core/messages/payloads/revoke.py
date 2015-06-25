# Copyright (c) 2015 Hewlett Packard Development Company, L.P.
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
from kmip.core import objects
from kmip.core import primitives

from kmip.core.primitives import Struct

from kmip.core.utils import BytearrayStream


class RevokeRequestPayload(Struct):
    """
    A request payload for the Revoke operation.

    The payload contains a UUID of a cryptographic object that that server
    should revoke. See Section 4.20 of the KMIP 1.1 specification for more
    information.

    Attributes:
        unique_identifier: The UUID of a managed cryptographic object
        revocation_reason: The reason why the object was revoked
        compromised_date: The date of compromise if the object was compromised
    """

    def __init__(self,
                 unique_identifier=None,
                 revocation_reason=None,
                 compromise_date=None):
        """
        Construct a RevokeRequestPayload object.
        Args:
            unique_identifier (UniqueIdentifier): The UUID of a managed
                cryptographic object.
            revocation_reason (RevocationReason): The reason why the object was
                revoked.
            compromise_date (DateTime): the date of compromise if the object
                was compromised.
        """
        super(RevokeRequestPayload, self).__init__(
            tag=enums.Tags.REQUEST_PAYLOAD)
        self.unique_identifier = unique_identifier
        self.compromise_date = compromise_date
        self.revocation_reason = revocation_reason
        if self.revocation_reason is None:
            self.revocation_reason = objects.RevocationReason()
        self.validate()

    def read(self, istream):
        """
        Read the data encoding the RevokeRequestPayload object and decode it
        into its constituent parts.
        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(RevokeRequestPayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.unique_identifier = attributes.UniqueIdentifier()
        self.unique_identifier.read(tstream)

        self.revocation_reason = objects.RevocationReason()
        self.revocation_reason.read(tstream)

        if self.is_tag_next(enums.Tags.COMPROMISE_OCCURRENCE_DATE, tstream):
            self.compromise_date = primitives.DateTime(
                tag=enums.Tags.COMPROMISE_OCCURRENCE_DATE)
            self.compromise_date.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the RevokeRequestPayload object to a stream.
        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        # Write the contents of the request payload
        if self.unique_identifier is not None:
            self.unique_identifier.write(tstream)

        self.revocation_reason.write(tstream)

        if self.compromise_date is not None:
            self.compromise_date.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(RevokeRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the ActivateRequestPayload object.
        """
        if self.unique_identifier is not None:
            if not isinstance(self.unique_identifier,
                              attributes.UniqueIdentifier):
                msg = "invalid unique identifier"
                raise TypeError(msg)
        if self.compromise_date is not None:
            if not isinstance(self.compromise_date, primitives.DateTime):
                msg = "invalid compromise time"
                raise TypeError(msg)
        if not isinstance(self.revocation_reason, objects.RevocationReason):
            msg = "invalid revocation reason"
            raise TypeError(msg)


class RevokeResponsePayload(Struct):
    """
    A response payload for the Revoke operation.
    The payload contains the server response to the initial Revoke request.
    See Section 4.20 of the KMIP 1.1 specification for more information.
    Attributes:
        unique_identifier: The UUID of a managed cryptographic object.
    """
    def __init__(self,
                 unique_identifier=None):
        """
        Construct a RevokeResponsePayload object.
        Args:
            unique_identifier (UniqueIdentifier): The UUID of a managed
                cryptographic object.
        """
        super(RevokeResponsePayload, self).__init__(
            tag=enums.Tags.RESPONSE_PAYLOAD)
        if unique_identifier is None:
            self.unique_identifier = attributes.UniqueIdentifier()
        else:
            self.unique_identifier = unique_identifier
        self.validate()

    def read(self, istream):
        """
        Read the data encoding the RevokeResponsePayload object and decode it
        into its constituent parts.
        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(RevokeResponsePayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.unique_identifier = attributes.UniqueIdentifier()
        self.unique_identifier.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the RevokeResponsePayload object to a stream.
        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        # Write the contents of the response payload
        self.unique_identifier.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(RevokeResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the RevokeRequestPayload object.
        """
        if not isinstance(self.unique_identifier, attributes.UniqueIdentifier):
            msg = "invalid unique identifier"
            raise TypeError(msg)
