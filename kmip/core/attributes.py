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

from kmip.core.enums import CertificateTypeEnum
from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import Tags

from kmip.core.errors import ErrorStrings

from kmip.core.misc import KeyFormatType

from kmip.core.primitives import ByteString
from kmip.core.primitives import Enumeration
from kmip.core.primitives import Integer
from kmip.core.primitives import Struct
from kmip.core.primitives import TextString

from kmip.core.utils import BytearrayStream
from enum import Enum


# 3.1
class UniqueIdentifier(TextString):

    def __init__(self, value=None, tag=Tags.UNIQUE_IDENTIFIER):
        super(UniqueIdentifier, self).__init__(value, tag)


class PrivateKeyUniqueIdentifier(UniqueIdentifier):

    def __init__(self, value=None):
        super(PrivateKeyUniqueIdentifier, self).__init__(
            value, Tags.PRIVATE_KEY_UNIQUE_IDENTIFIER)


class PublicKeyUniqueIdentifier(UniqueIdentifier):

    def __init__(self, value=None):
        super(PublicKeyUniqueIdentifier, self).__init__(
            value, Tags.PUBLIC_KEY_UNIQUE_IDENTIFIER)


# 3.2
class Name(Struct):

    class NameValue(TextString):

        def __init__(self, value=None):
            super(Name.NameValue, self).__init__(value, Tags.NAME_VALUE)

        def __eq__(self, other):
            if isinstance(other, Name.NameValue):
                if self.value == other.value:
                    return True
                else:
                    return False
            else:
                return NotImplemented

        def __repr__(self):
            return "{0}(value={1})".format(
                    type(self).__name__, repr(self.value))

        def __str__(self):
            return "{0}".format(self.value)

    class NameType(Enumeration):

        def __init__(self, value=None):
            super(Name.NameType, self).__init__(
                enums.NameType, value, Tags.NAME_TYPE)

        def __eq__(self, other):
            if isinstance(other, Name.NameType):
                if self.value == other.value:
                    return True
                else:
                    return False
            else:
                return NotImplemented

        def __repr__(self):
            return "{0}(value={1})".format(
                    type(self).__name__, repr(self.value))

        def __str__(self):
            return "{0}".format(self.value)

    def __init__(self, name_value=None, name_type=None):
        super(Name, self).__init__(tag=Tags.NAME)
        self.name_value = name_value
        self.name_type = name_type
        self.validate()

    def read(self, istream):
        super(Name, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the value and type of the name
        self.name_value = Name.NameValue()
        self.name_type = Name.NameType()
        self.name_value.read(tstream)
        self.name_type.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the value and type of the name
        self.name_value.write(tstream)
        self.name_type.write(tstream)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(Name, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        name = Name.__name__
        msg = ErrorStrings.BAD_EXP_RECV
        if self.name_value and \
                not isinstance(self.name_value, Name.NameValue) and \
                not isinstance(self.name_value, str):
            member = 'name_value'
            raise TypeError(msg.format('{0}.{1}'.format(name, member),
                                       'name_value', type(Name.NameValue),
                                       type(self.name_value)))
        if self.name_type and \
                not isinstance(self.name_type, Name.NameType) and \
                not isinstance(self.name_type, str):
            member = 'name_type'
            raise TypeError(msg.format('{0}.{1}'.format(name, member),
                                       'name_type', type(Name.NameType),
                                       type(self.name_type)))

    @classmethod
    def create(cls, name_value, name_type):
        '''
            Returns a Name object, populated with the given value and type
        '''
        if isinstance(name_value, Name.NameValue):
            value = name_value
        elif isinstance(name_value, str):
            value = cls.NameValue(name_value)
        else:
            name = 'Name'
            msg = ErrorStrings.BAD_EXP_RECV
            member = 'name_value'
            raise TypeError(msg.format('{0}.{1}'.format(name, member),
                                       'name_value', type(Name.NameValue),
                                       type(name_value)))

        if isinstance(name_type, Name.NameType):
            n_type = name_type
        elif isinstance(name_type, Enum):
            n_type = cls.NameType(name_type)
        else:
            name = 'Name'
            msg = ErrorStrings.BAD_EXP_RECV
            member = 'name_type'
            raise TypeError(msg.format('{0}.{1}'.format(name, member),
                                       'name_type', type(Name.NameType),
                                       type(name_type)))

        return Name(name_value=value,
                    name_type=n_type)

    def __repr__(self):
        return "{0}(type={1},value={2})".format(
                type(self).__name__,
                repr(self.name_type),
                repr(self.name_value))

    def __str__(self):
        return "{0}".format(self.name_value.value)

    def __eq__(self, other):
        if isinstance(other, Name):
            if self.name_value == other.name_value and \
                        self.name_type == other.name_type:
                return True
            else:
                return False
        else:
            return NotImplemented

    def __ne__(self, other):
        return not self.__eq__(other)


# 3.3
class ObjectType(Enumeration):

    def __init__(self, value=None):
        super(ObjectType, self).__init__(
            enums.ObjectType, value, Tags.OBJECT_TYPE)


# 3.4
class CryptographicAlgorithm(Enumeration):

    def __init__(self, value=None):
        super(CryptographicAlgorithm, self).__init__(
            enums.CryptographicAlgorithm, value, Tags.CRYPTOGRAPHIC_ALGORITHM)


# 3.5
class CryptographicLength(Integer):

    def __init__(self, value=None):
        super(CryptographicLength, self).__init__(
            value, Tags.CRYPTOGRAPHIC_LENGTH)


# 3.6
class HashingAlgorithm(Enumeration):
    """
    An encodeable wrapper for the HashingAlgorithm enumeration.

    Used to specify the algorithm used to compute the Digest of a Managed
    Object. See Sections 3.17 and 9.1.3.2.16 of the KMIP v1.1 specification
    for more information.
    """

    def __init__(self, value=HashingAlgorithmEnum.SHA_256):
        """
        Construct a HashingAlgorithm object.

        Args:
            value (HashingAlgorithm): A HashingAlgorithm enumeration value,
                (e.g., HashingAlgorithm.MD5). Optional, defaults to
                HashingAlgorithm.SHA_256.
        """
        super(HashingAlgorithm, self).__init__(
            enums.HashingAlgorithm, value, Tags.HASHING_ALGORITHM)


class CryptographicParameters(Struct):

    class BlockCipherMode(Enumeration):

        def __init__(self, value=None):
            super(CryptographicParameters.BlockCipherMode, self).__init__(
                enums.BlockCipherMode, value, Tags.BLOCK_CIPHER_MODE)

    class PaddingMethod(Enumeration):

        def __init__(self, value=None):
            super(CryptographicParameters.PaddingMethod, self).__init__(
                enums.PaddingMethod, value, Tags.PADDING_METHOD)

    class KeyRoleType(Enumeration):

        def __init__(self, value=None):
            super(CryptographicParameters.KeyRoleType, self).__init__(
                enums.KeyRoleType, value, Tags.KEY_ROLE_TYPE)

    class DigitalSignatureAlgorithm(Enumeration):

        def __init__(self, value=None):
            super(CryptographicParameters.DigitalSignatureAlgorithm,
                  self).__init__(enums.DigitalSignatureAlgorithm,
                                 value, Tags.DIGITAL_SIGNATURE_ALGORITHM)

    def __init__(self,
                 block_cipher_mode=None,
                 padding_method=None,
                 hashing_algorithm=None,
                 key_role_type=None,
                 digital_signature_algorithm=None,
                 cryptographic_algorithm=None):
        super(CryptographicParameters, self).__init__(
            tag=Tags.CRYPTOGRAPHIC_PARAMETERS)
        self.block_cipher_mode = block_cipher_mode
        self.padding_method = padding_method
        self.hashing_algorithm = hashing_algorithm
        self.key_role_type = key_role_type
        self.digital_signature_algorithm = digital_signature_algorithm
        self.cryptographic_algorithm = cryptographic_algorithm

    def read(self, istream):
        super(CryptographicParameters, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.BLOCK_CIPHER_MODE, tstream):
            self.block_cipher_mode = CryptographicParameters.BlockCipherMode()
            self.block_cipher_mode.read(tstream)

        if self.is_tag_next(Tags.PADDING_METHOD, tstream):
            self.padding_method = CryptographicParameters.PaddingMethod()
            self.padding_method.read(tstream)

        if self.is_tag_next(Tags.HASHING_ALGORITHM, tstream):
            self.hashing_algorithm = HashingAlgorithm()
            self.hashing_algorithm.read(tstream)

        if self.is_tag_next(Tags.KEY_ROLE_TYPE, tstream):
            self.key_role_type = CryptographicParameters.KeyRoleType()
            self.key_role_type.read(tstream)

        if self.is_tag_next(Tags.DIGITAL_SIGNATURE_ALGORITHM, tstream):
            self.digital_signature_algorithm = \
                CryptographicParameters.DigitalSignatureAlgorithm()
            self.digital_signature_algorithm.read(tstream)

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_ALGORITHM, tstream):
            self.cryptographic_algorithm = CryptographicAlgorithm()
            self.cryptographic_algorithm.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the request payload
        if self.block_cipher_mode is not None:
            self.block_cipher_mode.write(tstream)
        if self.padding_method is not None:
            self.padding_method.write(tstream)
        if self.hashing_algorithm is not None:
            self.hashing_algorithm.write(tstream)
        if self.key_role_type is not None:
            self.key_role_type.write(tstream)
        if self.digital_signature_algorithm is not None:
            self.digital_signature_algorithm.write(tstream)
        if self.cryptographic_algorithm is not None:
            self.cryptographic_algorithm.write(tstream)

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(CryptographicParameters, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        if self.block_cipher_mode is not None:
            if not isinstance(self.block_cipher_mode, self.BlockCipherMode):
                msg = "Invalid block cipher mode"
                msg += "; expected {0}, received {1}".format(
                    self.BlockCipherMode, self.block_cipher_mode)
                raise TypeError(msg)
        if self.padding_method is not None:
            if not isinstance(self.padding_method, self.PaddingMethod):
                msg = "Invalid padding method"
                msg += "; expected {0}, received {1}".format(
                    self.PaddingMethod, self.padding_method)
                raise TypeError(msg)
        if self.hashing_algorithm is not None:
            if not isinstance(self.hashing_algorithm, HashingAlgorithm):
                msg = "Invalid hashing algorithm"
                msg += "; expected {0}, received {1}".format(
                    HashingAlgorithm, self.hashing_algorithm)
                raise TypeError(msg)
        if self.key_role_type is not None:
            if not isinstance(self.key_role_type, self.KeyRoleType):
                msg = "Invalid key role type"
                msg += "; expected {0}, received {1}".format(
                    self.KeyRoleType, self.key_role_type)
                raise TypeError(msg)
        if self.digital_signature_algorithm is not None:
            if not isinstance(self.digital_signature_algorithm,
                              self.DigitalSignatureAlgorithm):
                msg = "Invalid digital signature algorithm"
                msg += "; expected {0}, received {1}".format(
                    self.DigitalSignatureAlgorithm,
                    self.digital_signature_algorithm)
                raise TypeError(msg)
        if self.cryptographic_algorithm is not None:
            if not isinstance(self.cryptographic_algorithm,
                              CryptographicAlgorithm):
                msg = "Invalid cryptograhic algorithm"
                msg += "; expected {0}, received {1}".format(
                    CryptographicAlgorithm, self.cryptographic_algorithm)
                raise TypeError(msg)

    def __eq__(self, other):
        if isinstance(other, CryptographicParameters):
            if self.block_cipher_mode != other.block_cipher_mode:
                return False
            elif self.key_role_type != other.key_role_type:
                return False
            elif self.hashing_algorithm != other.hashing_algorithm:
                return False
            elif self.digital_signature_algorithm \
                    != other.digital_signature_algorithm:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.padding_method != other.padding_method:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, CryptographicParameters):
            return not self == other
        else:
            return NotImplemented


class CertificateType(Enumeration):
    """
    An encodeable wrapper for the CertificateType enumeration.

    Used to specify the type of the encoded bytes of a Certificate Managed
    Object. See Sections 2.2.1 and 3.8 of the KMIP v1.1 specification for more
    information.
    """

    def __init__(self, value=CertificateTypeEnum.X_509):
        """
        Construct a CertificateType object.

        Args:
            value (CertificateTypeEnum): A CertificateTypeEnum enumeration
                value, (e.g., CertificateTypeEnum.PGP). Optional, defaults to
                CertificateTypeEnum.X_509.
        """
        super(CertificateType, self).__init__(
            enums.CertificateTypeEnum, value, Tags.CERTIFICATE_TYPE)


class DigestValue(ByteString):
    """
    A byte string representing the hash value of a Digest.

    Used to hold the bytes of the digest hash value. Automatically generated
    by the KMIP server, the value is empty if the server does not have access
    to the value or encoding of the related Managed Object. See Section 3.17
    of the KMIP 1.1 specification for more information.

    Attributes:
        value: The bytes of the hash.
    """

    def __init__(self, value=b''):
        """
        Construct a DigestValue object.

        Args:
            value (bytes): The bytes of the hash. Optional, defaults to
                the empty byte string.
        """
        super(DigestValue, self).__init__(value, Tags.DIGEST_VALUE)


class Digest(Struct):
    """
    A structure storing a hash digest of a Managed Object.

    Digests may be calculated for keys, secret data objects, certificates, and
    opaque data objects and are generated when the object is created or
    registered with the KMIP server. See Section 3.17 of the KMIP 1.1
    specification for more information.

    Attributes:
        hashing_algorithm: The algorithm used to compute the hash digest.
        digest_value: The bytes representing the hash digest value.
        key_format_type: The type of the key the hash was generated for.
    """

    def __init__(self,
                 hashing_algorithm=None,
                 digest_value=None,
                 key_format_type=None):
        """
        Construct a Digest object.

        Args:
            hashing_algorithm (HashingAlgorithm): The hash algorithm used to
                compute the value of the digest. Optional, defaults to None.
            digest_value (DigestValue): The byte string representing the
                value of the hash digest. Optional, defaults to None.
            key_format_type (KeyFormatType): The format type of the key the
                hash was computed for, if the object in question is a key.
                Optional, defaults to None.
        """
        super(Digest, self).__init__(Tags.DIGEST)

        if hashing_algorithm is None:
            self.hashing_algorithm = HashingAlgorithm()
        else:
            self.hashing_algorithm = hashing_algorithm

        if digest_value is None:
            self.digest_value = DigestValue()
        else:
            self.digest_value = digest_value

        if key_format_type is None:
            self.key_format_type = KeyFormatType()
        else:
            self.key_format_type = key_format_type

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the Digest object and decode it into its
        constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(Digest, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.hashing_algorithm.read(tstream)
        self.digest_value.read(tstream)
        self.key_format_type.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the Digest object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        self.hashing_algorithm.write(tstream)
        self.digest_value.write(tstream)
        self.key_format_type.write(tstream)

        self.length = tstream.length()
        super(Digest, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the Digest object.
        """
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Add checks comparing the length of the digest
        # value against the standard length for the stated hashing algorithm.
        if not isinstance(self.hashing_algorithm, HashingAlgorithm):
            msg = "invalid hashing algorithm"
            msg += "; expected {0}, received {1}".format(
                HashingAlgorithm, self.hashing_algorithm)
            raise TypeError(msg)

        if not isinstance(self.digest_value, DigestValue):
            msg = "invalid digest value"
            msg += "; expected {0}, received {1}".format(
                DigestValue, self.digest_value)
            raise TypeError(msg)

        if not isinstance(self.key_format_type, KeyFormatType):
            msg = "invalid key format type"
            msg += "; expected {0}, received {1}".format(
                KeyFormatType, self.key_format_type)
            raise TypeError(msg)

    def __eq__(self, other):
        if isinstance(other, Digest):
            if self.hashing_algorithm != other.hashing_algorithm:
                return False
            elif self.digest_value != other.digest_value:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, Digest):
            return not (self == other)
        else:
            return NotImplemented

    def __repr__(self):
        hashing_algorithm = "hashing_algorithm={0}".format(
            repr(self.hashing_algorithm))
        digest_value = "digest_value={0}".format(
            repr(self.digest_value))
        key_format_type = "key_format_type={0}".format(
            repr(self.key_format_type))

        return "Digest({0}, {1}, {2})".format(
            hashing_algorithm, digest_value, key_format_type)

    def __str__(self):
        return str(self.digest_value)

    @classmethod
    def create(cls,
               hashing_algorithm=HashingAlgorithmEnum.SHA_256,
               digest_value=b'',
               key_format_type=KeyFormatTypeEnum.RAW):
        """
        Construct a Digest object from provided digest values.

        Args:
            hashing_algorithm (HashingAlgorithm): An enumeration representing
                the hash algorithm used to compute the digest. Optional,
                defaults to HashingAlgorithm.SHA_256.
            digest_value (byte string): The bytes of the digest hash. Optional,
                defaults to the empty byte string.
            key_format_type (KeyFormatType): An enumeration representing the
                format of the key corresponding to the digest. Optional,
                defaults to KeyFormatType.RAW.

        Returns:
            Digest: The newly created Digest.

        Example:
            >>> x = Digest.create(HashingAlgorithm.MD5, b'\x00',
            ... KeyFormatType.RAW)
            >>> x.hashing_algorithm
            HashingAlgorithm(value=HashingAlgorithm.MD5)
            >>> x.digest_value
            DigestValue(value=bytearray(b'\x00'))
            >>> x.key_format_type
            KeyFormatType(value=KeyFormatType.RAW)
        """
        algorithm = HashingAlgorithm(hashing_algorithm)
        value = DigestValue(bytearray(digest_value))
        format_type = KeyFormatType(key_format_type)

        return Digest(hashing_algorithm=algorithm,
                      digest_value=value,
                      key_format_type=format_type)


# 3.18
class OperationPolicyName(TextString):

    def __init__(self, value=None):
        super(OperationPolicyName, self).__init__(
            value, Tags.OPERATION_POLICY_NAME)


# 3.19
class CryptographicUsageMask(Integer):

    ENUM_TYPE = enums.CryptographicUsageMask

    def __init__(self, value=None):
        super(CryptographicUsageMask, self).__init__(
            value, Tags.CRYPTOGRAPHIC_USAGE_MASK)


class State(Enumeration):

    def __init__(self, value=None):
        super(State, self).__init__(enums.State, value, Tags.STATE)


# 3.33
class ObjectGroup(TextString):

    def __init__(self, value=None):
        super(ObjectGroup, self).__init__(value, Tags.OBJECT_GROUP)


# 3.36
class ApplicationNamespace(TextString):
    """
    The name of a namespace supported by the KMIP server.

    A part of ApplicationSpecificInformation, sets of these are also potential
    responses to a Query request. See Sections 3.36 and 4.25 of the KMIP v1.1
    specification for more information.
    """

    def __init__(self, value=None):
        """
        Construct an ApplicationNamespace object.

        Args:
            value (str): A string representing a namespace. Optional, defaults
                to None.
        """
        super(ApplicationNamespace, self).__init__(
            value, Tags.APPLICATION_NAMESPACE)


class ApplicationData(TextString):
    """
    A string representing data specific to an application namespace.

    A part of ApplicationSpecificInformation. See Section 3.36 of the KMIP v1.1
    specification for more information.
    """

    def __init__(self, value=None):
        """
        Construct an ApplicationData object.

        Args:
            value (str): A string representing data for a particular namespace.
                Optional, defaults to None.
        """
        super(ApplicationData, self).__init__(value, Tags.APPLICATION_DATA)


class ApplicationSpecificInformation(Struct):
    """
    A structure used to store data specific to the applications that use a
    Managed Object.

    An attribute of Managed Objects, it may be specified during the creation or
    modification of any server Managed Object.

    Attributes:
        application_namespace: The name of a namespace supported by the server.
        application_data: String data relevant to the specified namespace.

    See Section 3.36 of the KMIP v1.1 specification for more information.
    """

    def __init__(self, application_namespace=None, application_data=None):
        """
        Construct an ApplicationSpecificInformation object.

        Args:
            application_namespace (ApplicationNamespace): The name of a
                namespace supported by the server. Optional, defaults to None.
            application_data (ApplicationData): String data relevant to the
                specified namespace. Optional, defaults to None.
        """
        super(ApplicationSpecificInformation, self).__init__(
            Tags.APPLICATION_SPECIFIC_INFORMATION)

        if application_namespace is None:
            self.application_namespace = ApplicationNamespace()
        else:
            self.application_namespace = application_namespace

        if application_data is None:
            self.application_data = ApplicationData()
        else:
            self.application_data = application_data

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the ApplicationSpecificInformation object and
        decode it into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(ApplicationSpecificInformation, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.application_namespace.read(tstream)
        self.application_data.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the ApplicationSpecificInformation object to a
        stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        self.application_namespace.write(tstream)
        self.application_data.write(tstream)

        self.length = tstream.length()
        super(ApplicationSpecificInformation, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the types of the different attributes of the
        ApplicationSpecificInformation object.
        """
        self.__validate()

    def __repr__(self):
        application_namespace = "application_namespace={0}".format(
            repr(self.application_namespace)
        )
        application_data = "application_data={0}".format(
            repr(self.application_data)
        )
        return "ApplicationSpecificInformation({0}, {1})".format(
            application_namespace,
            application_data
        )

    def __str__(self):
        return str({
            "application_namespace": str(self.application_namespace),
            "application_data": str(self.application_data)
        })

    def __eq__(self, other):
        if isinstance(other, ApplicationSpecificInformation):
            if self.application_namespace != other.application_namespace:
                return False
            if self.application_data != other.application_data:
                return False
            return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ApplicationSpecificInformation):
            return not self.__eq__(other)
        else:
            return NotImplemented

    def __validate(self):
        if not isinstance(self.application_namespace, ApplicationNamespace):
            msg = "invalid application namespace"
            msg += "; expected {0}, received {1}".format(
                ApplicationNamespace, self.application_namespace)
            raise TypeError(msg)

        if not isinstance(self.application_data, ApplicationData):
            msg = "invalid application data"
            msg += "; expected {0}, received {1}".format(
                ApplicationData, self.application_data)
            raise TypeError(msg)

    @classmethod
    def create(cls, application_namespace, application_data):
        """
        Construct an ApplicationSpecificInformation object from provided data
        and namespace values.

        Args:
            application_namespace (str): The name of the application namespace.
            application_data (str): Application data related to the namespace.

        Returns:
            ApplicationSpecificInformation: The newly created set of
                application information.

        Example:
            >>> x = ApplicationSpecificInformation.create('namespace', 'data')
            >>> x.application_namespace.value
            'namespace'
            >>> x.application_data.value
            'data'
        """
        namespace = ApplicationNamespace(application_namespace)
        data = ApplicationData(application_data)
        return ApplicationSpecificInformation(
            application_namespace=namespace, application_data=data)


# 3.37
class ContactInformation(TextString):

    def __init__(self, value=None):
        super(ContactInformation, self).__init__(
            value, Tags.CONTACT_INFORMATION)


# 3.39
# TODO (peter-hamilton) A CustomAttribute TextString is not sufficient to
# TODO (peter-hamilton) cover all potential custom attributes. This is a
# TODO (peter-hamilton) temporary stopgap.
class CustomAttribute(TextString):

    def __init__(self, value=None):
        super(CustomAttribute, self).__init__(value, Tags.ATTRIBUTE_VALUE)
