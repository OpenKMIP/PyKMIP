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
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import Tags
from kmip.core.enums import QueryFunction as QueryFunctionEnum

from kmip.core.primitives import ByteString
from kmip.core.primitives import Enumeration
from kmip.core.primitives import Interval
from kmip.core.primitives import Struct
from kmip.core.primitives import TextString

from kmip.core.utils import BytearrayStream

class CertificateValue(ByteString):
    """
    The bytes of a DER-encoded X.509 public key certificate.

    Used by the Certificate Managed Object to store the bytes of the
    certificate. See Section 2.2.1 of the KMIP 1.1. specification for more
    information.
    """

    def __init__(self, value=b''):
        """
        Construct a CertificateValue byte string.

        Args:
            value (bytes): A byte string (e.g., b'\x00\x01...') containing the
                certificate bytes to store. Optional, defaults to the empty
                byte string.
        """
        super(CertificateValue, self).__init__(value, Tags.CERTIFICATE_VALUE)

class Offset(Interval):
    """
    An integer representing a positive change in time.

    Used by Rekey and Recertify requests to indicate the time difference
    between the InitializationDate and the ActivationDate of the replacement
    item to be created. See Sections 4.4, 4.5, and 4.8 of the KMIP 1.1
    specification for more information.
    """

    def __init__(self, value=None):
        """
        Construct an Offset object.

        Args:
            value (int): An integer representing a positive change in time.
                Optional, defaults to None.
        """
        super(Offset, self).__init__(value, Tags.OFFSET)

class QueryFunction(Enumeration):
    """
    An encodeable wrapper for the QueryFunction enumeration.

    Used by Query requests to specify the information to retrieve from the
    KMIP server. See Sections 4.25 and 9.1.3.2.24 of the KMIP 1.1
    specification for more information.
    """

    def __init__(self, value=None):
        """
        Construct a QueryFunction object.

        Args:
            value (QueryFunction enum): A QueryFunction enumeration value,
                (e.g., QueryFunction.QUERY_OPERATIONS). Optional, default to
                None.
        """
        super(QueryFunction, self).__init__(
            QueryFunctionEnum, value, Tags.QUERY_FUNCTION)

class VendorIdentification(TextString):
    """
    A text string uniquely identifying a KMIP vendor.

    Returned by KMIP servers upon receipt of a Query request for server
    information. See Section 4.25 of the KMIP 1.1. specification for more
    information.
    """

    def __init__(self, value=None):
        """
        Construct a VendorIdentification object.

        Args:
            value (str): A string describing a KMIP vendor. Optional, defaults
                to None.
        """
        super(VendorIdentification, self).__init__(
            value, Tags.VENDOR_IDENTIFICATION)

class ServerInformation(Struct):
    """
    A structure containing vendor-specific fields and/or substructures.

    Returned by KMIP servers upon receipt of a Query request for server
    information. See Section 4.25 of the KMIP 1.1 specification for more
    information.

    Note:
    There are no example structures nor data encodings in the KMIP
    documentation of this object. Therefore this class handles encoding and
    decoding its data in a generic way, using a BytearrayStream for primary
    storage. The intent is for vendor-specific subclasses to decide how to
    decode this data from the stream attribute. Likewise, these subclasses
    must decide how to encode their data into the stream attribute. There
    are no arguments to the constructor and therefore no means by which to
    validate the object's contents.
    """

    def __init__(self):
        """
        Construct a ServerInformation object.
        """
        super(ServerInformation, self).__init__(Tags.SERVER_INFORMATION)

        self.data = BytearrayStream()

        self.validate()

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the ServerInformation object and decode it into
        its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(ServerInformation, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.data = BytearrayStream(tstream.read())

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the ServerInformation object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        tstream = BytearrayStream()
        tstream.write(self.data.buffer)

        self.length = tstream.length()
        super(ServerInformation, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the types of the different parts of the ServerInformation
        object.
        """
        self.__validate()

    def __validate(self):
        # NOTE (peter-hamilton): Intentional pass, no way to validate data.
        pass

    def __eq__(self, other):
        if isinstance(other, ServerInformation):
            if len(self.data) != len(other.data):
                return False
            elif self.data != other.data:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ServerInformation):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        return "ServerInformation()"

    def __str__(self):
        return str(self.data)

class KeyFormatType(Enumeration):
    """
    An encodeable wrapper for the KeyFormatType enumeration.

    Used to identify the format of different types of keys in KeyBlock and
    Digest objects, it can also be used to specify the format in which a key
    is returned when using the Get operation. See Sections 2.1.3, 2.1.7, 3.17,
    4.11, and 9.1.3.2.3 of the KMIP 1.1 specification for more information.
    """

    def __init__(self, value=KeyFormatTypeEnum.RAW):
        """
        Construct a KeyFormatType object.

        Args:
            value (KeyFormatType): A KeyFormatType enumeration value,
                (e.g., KeyFormatType.PKCS_1). Optional, default to
                KeyFormatType.RAW.
        """
        super(KeyFormatType, self).__init__(
            KeyFormatTypeEnum, value, Tags.KEY_FORMAT_TYPE)
