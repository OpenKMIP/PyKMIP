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
from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import Tags

from kmip.core import exceptions

from kmip.core.misc import KeyFormatType

from kmip.core import primitives
from kmip.core.primitives import Boolean
from kmip.core.primitives import ByteString
from kmip.core.primitives import Enumeration
from kmip.core.primitives import Integer
from kmip.core.primitives import Struct
from kmip.core.primitives import TextString

from kmip.core import utils
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

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(Name, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the value and type of the name
        self.name_value = Name.NameValue()
        self.name_type = Name.NameType()
        self.name_value.read(tstream, kmip_version=kmip_version)
        self.name_type.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        # Write the value and type of the name
        self.name_value.write(tstream, kmip_version=kmip_version)
        self.name_type.write(tstream, kmip_version=kmip_version)

        # Write the length and value of the template attribute
        self.length = tstream.length()
        super(Name, self).write(ostream, kmip_version=kmip_version)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        name = Name.__name__
        msg = exceptions.ErrorStrings.BAD_EXP_RECV
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
            msg = exceptions.ErrorStrings.BAD_EXP_RECV
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
            msg = exceptions.ErrorStrings.BAD_EXP_RECV
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
    """
    A set of values for cryptographic operations.

    A structure containing optional fields describing certain cryptographic
    parameters to be used when performing cryptographic operations with the
    associated KMIP object.
    """

    def __init__(self,
                 block_cipher_mode=None,
                 padding_method=None,
                 hashing_algorithm=None,
                 key_role_type=None,
                 digital_signature_algorithm=None,
                 cryptographic_algorithm=None,
                 random_iv=None,
                 iv_length=None,
                 tag_length=None,
                 fixed_field_length=None,
                 invocation_field_length=None,
                 counter_length=None,
                 initial_counter_value=None):
        super(CryptographicParameters, self).__init__(
            tag=Tags.CRYPTOGRAPHIC_PARAMETERS)

        self._block_cipher_mode = None
        self._padding_method = None
        self._hashing_algorithm = None
        self._key_role_type = None
        self._digital_signature_algorithm = None
        self._cryptographic_algorithm = None
        self._random_iv = None
        self._iv_length = None
        self._tag_length = None
        self._fixed_field_length = None
        self._invocation_field_length = None
        self._counter_length = None
        self._initial_counter_value = None

        self.block_cipher_mode = block_cipher_mode
        self.padding_method = padding_method
        self.hashing_algorithm = hashing_algorithm
        self.key_role_type = key_role_type
        self.digital_signature_algorithm = digital_signature_algorithm
        self.cryptographic_algorithm = cryptographic_algorithm
        self.random_iv = random_iv
        self.iv_length = iv_length
        self.tag_length = tag_length
        self.fixed_field_length = fixed_field_length
        self.invocation_field_length = invocation_field_length
        self.counter_length = counter_length
        self.initial_counter_value = initial_counter_value

    @property
    def block_cipher_mode(self):
        if self._block_cipher_mode:
            return self._block_cipher_mode.value
        else:
            return None

    @block_cipher_mode.setter
    def block_cipher_mode(self, value):
        if value is None:
            self._block_cipher_mode = None
        elif isinstance(value, enums.BlockCipherMode):
            self._block_cipher_mode = Enumeration(
                enums.BlockCipherMode,
                value=value,
                tag=Tags.BLOCK_CIPHER_MODE
            )
        else:
            raise TypeError(
                "block cipher mode must be a BlockCipherMode enumeration"
            )

    @property
    def padding_method(self):
        if self._padding_method:
            return self._padding_method.value
        else:
            return None

    @padding_method.setter
    def padding_method(self, value):
        if value is None:
            self._padding_method = None
        elif isinstance(value, enums.PaddingMethod):
            self._padding_method = Enumeration(
                enums.PaddingMethod,
                value=value,
                tag=Tags.PADDING_METHOD
            )
        else:
            raise TypeError(
                "padding method must be a PaddingMethod enumeration"
            )

    @property
    def hashing_algorithm(self):
        if self._hashing_algorithm:
            return self._hashing_algorithm.value
        else:
            return None

    @hashing_algorithm.setter
    def hashing_algorithm(self, value):
        if value is None:
            self._hashing_algorithm = None
        elif isinstance(value, enums.HashingAlgorithm):
            self._hashing_algorithm = Enumeration(
                enums.HashingAlgorithm,
                value=value,
                tag=Tags.HASHING_ALGORITHM
            )
        else:
            raise TypeError(
                "hashing algorithm must be a HashingAlgorithm enumeration"
            )

    @property
    def key_role_type(self):
        if self._key_role_type:
            return self._key_role_type.value
        else:
            return None

    @key_role_type.setter
    def key_role_type(self, value):
        if value is None:
            self._key_role_type = None
        elif isinstance(value, enums.KeyRoleType):
            self._key_role_type = Enumeration(
                enums.KeyRoleType,
                value=value,
                tag=Tags.KEY_ROLE_TYPE
            )
        else:
            raise TypeError(
                "key role type must be a KeyRoleType enumeration"
            )

    @property
    def digital_signature_algorithm(self):
        if self._digital_signature_algorithm:
            return self._digital_signature_algorithm.value
        else:
            return None

    @digital_signature_algorithm.setter
    def digital_signature_algorithm(self, value):
        if value is None:
            self._digital_signature_algorithm = None
        elif isinstance(value, enums.DigitalSignatureAlgorithm):
            self._digital_signature_algorithm = Enumeration(
                enums.DigitalSignatureAlgorithm,
                value=value,
                tag=Tags.DIGITAL_SIGNATURE_ALGORITHM
            )
        else:
            raise TypeError(
                "digital signature algorithm must be a "
                "DigitalSignatureAlgorithm enumeration"
            )

    @property
    def cryptographic_algorithm(self):
        if self._cryptographic_algorithm:
            return self._cryptographic_algorithm.value
        else:
            return None

    @cryptographic_algorithm.setter
    def cryptographic_algorithm(self, value):
        if value is None:
            self._cryptographic_algorithm = None
        elif isinstance(value, enums.CryptographicAlgorithm):
            self._cryptographic_algorithm = Enumeration(
                enums.CryptographicAlgorithm,
                value=value,
                tag=Tags.CRYPTOGRAPHIC_ALGORITHM
            )
        else:
            raise TypeError(
                "cryptographic algorithm must be a CryptographicAlgorithm "
                "enumeration"
            )

    @property
    def random_iv(self):
        if self._random_iv:
            return self._random_iv.value
        else:
            return None

    @random_iv.setter
    def random_iv(self, value):
        if value is None:
            self._random_iv = None
        elif isinstance(value, bool):
            self._random_iv = Boolean(
                value=value,
                tag=Tags.RANDOM_IV
            )
        else:
            raise TypeError("random iv must be a boolean")

    @property
    def iv_length(self):
        if self._iv_length:
            return self._iv_length.value
        else:
            return None

    @iv_length.setter
    def iv_length(self, value):
        if value is None:
            self._iv_length = None
        elif isinstance(value, int):
            self._iv_length = Integer(
                value=value,
                tag=Tags.IV_LENGTH
            )
        else:
            raise TypeError("iv length must be an integer")

    @property
    def tag_length(self):
        if self._tag_length:
            return self._tag_length.value
        else:
            return None

    @tag_length.setter
    def tag_length(self, value):
        if value is None:
            self._tag_length = None
        elif isinstance(value, int):
            self._tag_length = Integer(
                value=value,
                tag=Tags.TAG_LENGTH
            )
        else:
            raise TypeError("tag length must be an integer")

    @property
    def fixed_field_length(self):
        if self._fixed_field_length:
            return self._fixed_field_length.value
        else:
            return None

    @fixed_field_length.setter
    def fixed_field_length(self, value):
        if value is None:
            self._fixed_field_length = None
        elif isinstance(value, int):
            self._fixed_field_length = Integer(
                value=value,
                tag=Tags.FIXED_FIELD_LENGTH
            )
        else:
            raise TypeError("fixed field length must be an integer")

    @property
    def invocation_field_length(self):
        if self._invocation_field_length:
            return self._invocation_field_length.value
        else:
            return None

    @invocation_field_length.setter
    def invocation_field_length(self, value):
        if value is None:
            self._invocation_field_length = None
        elif isinstance(value, int):
            self._invocation_field_length = Integer(
                value=value,
                tag=Tags.INVOCATION_FIELD_LENGTH
            )
        else:
            raise TypeError("invocation field length must be an integer")

    @property
    def counter_length(self):
        if self._counter_length:
            return self._counter_length.value
        else:
            return None

    @counter_length.setter
    def counter_length(self, value):
        if value is None:
            self._counter_length = None
        elif isinstance(value, int):
            self._counter_length = Integer(
                value=value,
                tag=Tags.COUNTER_LENGTH
            )
        else:
            raise TypeError("counter length must be an integer")

    @property
    def initial_counter_value(self):
        if self._initial_counter_value:
            return self._initial_counter_value.value
        else:
            return None

    @initial_counter_value.setter
    def initial_counter_value(self, value):
        if value is None:
            self._initial_counter_value = None
        elif isinstance(value, int):
            self._initial_counter_value = Integer(
                value=value,
                tag=Tags.INITIAL_COUNTER_VALUE
            )
        else:
            raise TypeError("initial counter value must be an integer")

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        super(CryptographicParameters, self).read(
            istream,
            kmip_version=kmip_version
        )
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.BLOCK_CIPHER_MODE, tstream):
            self._block_cipher_mode = Enumeration(
                enums.BlockCipherMode,
                tag=Tags.BLOCK_CIPHER_MODE
            )
            self._block_cipher_mode.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.PADDING_METHOD, tstream):
            self._padding_method = Enumeration(
                enums.PaddingMethod,
                tag=Tags.PADDING_METHOD
            )
            self._padding_method.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.HASHING_ALGORITHM, tstream):
            self._hashing_algorithm = Enumeration(
                enums.HashingAlgorithm,
                tag=Tags.HASHING_ALGORITHM
            )
            self._hashing_algorithm.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.KEY_ROLE_TYPE, tstream):
            self._key_role_type = Enumeration(
                enums.KeyRoleType,
                tag=Tags.KEY_ROLE_TYPE
            )
            self._key_role_type.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.DIGITAL_SIGNATURE_ALGORITHM, tstream):
            self._digital_signature_algorithm = Enumeration(
                enums.DigitalSignatureAlgorithm,
                tag=Tags.DIGITAL_SIGNATURE_ALGORITHM
            )
            self._digital_signature_algorithm.read(
                tstream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(Tags.CRYPTOGRAPHIC_ALGORITHM, tstream):
            self._cryptographic_algorithm = Enumeration(
                enums.CryptographicAlgorithm,
                tag=Tags.CRYPTOGRAPHIC_ALGORITHM
            )
            self._cryptographic_algorithm.read(
                tstream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(Tags.RANDOM_IV, tstream):
            self._random_iv = Boolean(tag=Tags.RANDOM_IV)
            self._random_iv.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.IV_LENGTH, tstream):
            self._iv_length = Integer(tag=Tags.IV_LENGTH)
            self._iv_length.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.TAG_LENGTH, tstream):
            self._tag_length = Integer(tag=Tags.TAG_LENGTH)
            self._tag_length.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.FIXED_FIELD_LENGTH, tstream):
            self._fixed_field_length = Integer(tag=Tags.FIXED_FIELD_LENGTH)
            self._fixed_field_length.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.INVOCATION_FIELD_LENGTH, tstream):
            self._invocation_field_length = Integer(
                tag=Tags.INVOCATION_FIELD_LENGTH
            )
            self._invocation_field_length.read(
                tstream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(Tags.COUNTER_LENGTH, tstream):
            self._counter_length = Integer(tag=Tags.COUNTER_LENGTH)
            self._counter_length.read(tstream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.INITIAL_COUNTER_VALUE, tstream):
            self._initial_counter_value = Integer(
                tag=Tags.INITIAL_COUNTER_VALUE
            )
            self._initial_counter_value.read(
                tstream,
                kmip_version=kmip_version
            )

        self.is_oversized(tstream)

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        tstream = BytearrayStream()

        if self._block_cipher_mode:
            self._block_cipher_mode.write(tstream, kmip_version=kmip_version)
        if self._padding_method:
            self._padding_method.write(tstream, kmip_version=kmip_version)
        if self._hashing_algorithm:
            self._hashing_algorithm.write(tstream, kmip_version=kmip_version)
        if self._key_role_type:
            self._key_role_type.write(tstream, kmip_version=kmip_version)
        if self._digital_signature_algorithm:
            self._digital_signature_algorithm.write(
                tstream,
                kmip_version=kmip_version
            )
        if self._cryptographic_algorithm:
            self._cryptographic_algorithm.write(
                tstream,
                kmip_version=kmip_version
            )
        if self._random_iv:
            self._random_iv.write(tstream, kmip_version=kmip_version)
        if self._iv_length:
            self._iv_length.write(tstream, kmip_version=kmip_version)
        if self._tag_length:
            self._tag_length.write(tstream, kmip_version=kmip_version)
        if self._fixed_field_length:
            self._fixed_field_length.write(tstream, kmip_version=kmip_version)
        if self._invocation_field_length:
            self._invocation_field_length.write(
                tstream,
                kmip_version=kmip_version
            )
        if self._counter_length:
            self._counter_length.write(tstream, kmip_version=kmip_version)
        if self._initial_counter_value:
            self._initial_counter_value.write(
                tstream,
                kmip_version=kmip_version
            )

        self.length = tstream.length()
        super(CryptographicParameters, self).write(
            ostream,
            kmip_version=kmip_version
        )
        ostream.write(tstream.buffer)

    def __eq__(self, other):
        if isinstance(other, CryptographicParameters):
            if self.block_cipher_mode != other.block_cipher_mode:
                return False
            elif self.padding_method != other.padding_method:
                return False
            elif self.hashing_algorithm != other.hashing_algorithm:
                return False
            elif self.key_role_type != other.key_role_type:
                return False
            elif self.digital_signature_algorithm \
                    != other.digital_signature_algorithm:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.random_iv != other.random_iv:
                return False
            elif self.iv_length != other.iv_length:
                return False
            elif self.tag_length != other.tag_length:
                return False
            elif self.fixed_field_length != other.fixed_field_length:
                return False
            elif self.invocation_field_length != other.invocation_field_length:
                return False
            elif self.counter_length != other.counter_length:
                return False
            elif self.initial_counter_value != other.initial_counter_value:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, CryptographicParameters):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "block_cipher_mode={0}".format(self.block_cipher_mode),
            "padding_method={0}".format(self.padding_method),
            "hashing_algorithm={0}".format(self.hashing_algorithm),
            "key_role_type={0}".format(self.key_role_type),
            "digital_signature_algorithm={0}".format(
                self.digital_signature_algorithm
            ),
            "cryptographic_algorithm={0}".format(
                self.cryptographic_algorithm
            ),
            "random_iv={0}".format(self.random_iv),
            "iv_length={0}".format(self.iv_length),
            "tag_length={0}".format(self.tag_length),
            "fixed_field_length={0}".format(self.fixed_field_length),
            "invocation_field_length={0}".format(
                self.invocation_field_length
            ),
            "counter_length={0}".format(self.counter_length),
            "initial_counter_value={0}".format(self.initial_counter_value)
        ])
        return "CryptographicParameters({0})".format(args)

    def __str__(self):
        return str({
            'block_cipher_mode': self.block_cipher_mode,
            'padding_method': self.padding_method,
            'hashing_algorithm': self.hashing_algorithm,
            'key_role_type': self.key_role_type,
            'digital_signature_algorithm': self.digital_signature_algorithm,
            'cryptographic_algorithm': self.cryptographic_algorithm,
            'random_iv': self.random_iv,
            'iv_length': self.iv_length,
            'tag_length': self.tag_length,
            'fixed_field_length': self.fixed_field_length,
            'invocation_field_length': self.invocation_field_length,
            'counter_length': self.counter_length,
            'initial_counter_value': self.initial_counter_value
        })

class CertificateType(Enumeration):
    """
    An encodeable wrapper for the CertificateType enumeration.

    Used to specify the type of the encoded bytes of a Certificate Managed
    Object. See Sections 2.2.1 and 3.8 of the KMIP v1.1 specification for more
    information.
    """

    def __init__(self, value=enums.CertificateType.X_509):
        """
        Construct a CertificateType object.

        Args:
            value (CertificateType): A CertificateType enumeration
                value, (e.g., CertificateType.PGP). Optional, defaults to
                CertificateType.X_509.
        """
        super(CertificateType, self).__init__(
            enums.CertificateType, value, Tags.CERTIFICATE_TYPE)

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

    def read(self, istream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the Digest object and decode it into its
        constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(Digest, self).read(istream, kmip_version=kmip_version)
        tstream = BytearrayStream(istream.read(self.length))

        self.hashing_algorithm.read(tstream, kmip_version=kmip_version)
        self.digest_value.read(tstream, kmip_version=kmip_version)
        self.key_format_type.read(tstream, kmip_version=kmip_version)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the Digest object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        tstream = BytearrayStream()

        self.hashing_algorithm.write(tstream, kmip_version=kmip_version)
        self.digest_value.write(tstream, kmip_version=kmip_version)
        self.key_format_type.write(tstream, kmip_version=kmip_version)

        self.length = tstream.length()
        super(Digest, self).write(ostream, kmip_version=kmip_version)
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

class ApplicationSpecificInformation(primitives.Struct):
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
            application_namespace (string): The name of a namespace supported
                by the server. Optional, defaults to None. Required for
                read/write.
            application_data (string): String data relevant to the specified
                namespace. Optional, defaults to None. Required for read/write.
        """
        super(ApplicationSpecificInformation, self).__init__(
            enums.Tags.APPLICATION_SPECIFIC_INFORMATION
        )

        self._application_namespace = None
        self._application_data = None

        self.application_namespace = application_namespace
        self.application_data = application_data

    @property
    def application_namespace(self):
        if self._application_namespace:
            return self._application_namespace.value
        return None

    @application_namespace.setter
    def application_namespace(self, value):
        if value is None:
            self._application_namespace = None
        elif isinstance(value, str):
            self._application_namespace = primitives.TextString(
                value=value,
                tag=enums.Tags.APPLICATION_NAMESPACE
            )
        else:
            raise TypeError("The application namespace must be a string.")

    @property
    def application_data(self):
        if self._application_data:
            return self._application_data.value
        return None

    @application_data.setter
    def application_data(self, value):
        if value is None:
            self._application_data = None
        elif isinstance(value, str):
            self._application_data = primitives.TextString(
                value=value,
                tag=enums.Tags.APPLICATION_DATA
            )
        else:
            raise TypeError("The application data must be a string.")

    def read(self, input_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the ApplicationSpecificInformation attribute
        and decode it.

        Args:
            input_buffer (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(ApplicationSpecificInformation, self).read(
            input_buffer,
            kmip_version=kmip_version
        )
        local_buffer = utils.BytearrayStream(input_buffer.read(self.length))

        if self.is_tag_next(enums.Tags.APPLICATION_NAMESPACE, local_buffer):
            self._application_namespace = primitives.TextString(
                tag=enums.Tags.APPLICATION_NAMESPACE
            )
            self._application_namespace.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ApplicationSpecificInformation encoding is missing the "
                "ApplicationNamespace field."
            )
        if self.is_tag_next(enums.Tags.APPLICATION_DATA, local_buffer):
            self._application_data = primitives.TextString(
                tag=enums.Tags.APPLICATION_DATA
            )
            self._application_data.read(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidKmipEncoding(
                "The ApplicationSpecificInformation encoding is missing the "
                "ApplicationData field."
            )

        self.is_oversized(local_buffer)

    def write(self, output_buffer, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the ApplicationSpecificInformation object to a
        buffer.

        Args:
            output_buffer (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_buffer = utils.BytearrayStream()

        if self._application_namespace:
            self._application_namespace.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The ApplicationSpecificInformation object is missing the "
                "ApplicationNamespace field."
            )
        if self._application_data:
            self._application_data.write(
                local_buffer,
                kmip_version=kmip_version
            )
        else:
            raise exceptions.InvalidField(
                "The ApplicationSpecificInformation object is missing the "
                "ApplicationData field."
            )

        self.length = local_buffer.length()
        super(ApplicationSpecificInformation, self).write(
            output_buffer,
            kmip_version=kmip_version
        )
        output_buffer.write(local_buffer.buffer)

    def __repr__(self):
        args = [
            "application_namespace={}".format(
                repr(self.application_namespace)
            ),
            "application_data={}".format(repr(self.application_data))
        ]
        return "ApplicationSpecificInformation({})".format(", ".join(args))

    def __str__(self):
        value = ", ".join(
            [
                '"application_namespace": "{}"'.format(
                    self.application_namespace
                ),
                '"application_data": "{}"'.format(self.application_data)
            ]
        )
        return "{" + value + "}"

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

class DerivationParameters(Struct):
    """
    A set of values needed for key or secret derivation.

    A structure containing optional fields describing certain cryptographic
    parameters to be used when performing key or secret derivation operations.
    """

    def __init__(self,
                 cryptographic_parameters=None,
                 initialization_vector=None,
                 derivation_data=None,
                 salt=None,
                 iteration_count=None):
        """
        Construct a DerivationParameters struct.

        Args:
            cryptographic_parameters (CryptographicParameters): A
                CryptographicParameters struct containing the settings for
                the derivation process. Optional, defaults to None. If not
                included, the CryptographicParameters associated with the
                managed object will be used instead.
            initialization_vector (bytes): The IV value to be used with the
                pseudo-random derivation function (PRF). Optional depending
                on the PRF, defaults to None.
            derivation_data (bytes): A data component to be used instead of
                or with a derivation key to derive the new cryptographic
                object. Optional, defaults to None.
            salt (bytes): A salt value required by the PBKDF2 algorithm.
                Optional, defaults to None.
            iteration_count (bytes): An iteration count value required by
                the PBKDF2 algorithm. Optional, defaults to None.
        """
        super(DerivationParameters, self).__init__(
            tag=Tags.DERIVATION_PARAMETERS
        )

        self._cryptographic_parameters = None
        self._initialization_vector = None
        self._derivation_data = None
        self._salt = None
        self._iteration_count = None

        self.cryptographic_parameters = cryptographic_parameters
        self.initialization_vector = initialization_vector
        self.derivation_data = derivation_data
        self.salt = salt
        self.iteration_count = iteration_count

    @property
    def cryptographic_parameters(self):
        return self._cryptographic_parameters

    @cryptographic_parameters.setter
    def cryptographic_parameters(self, value):
        if value is None:
            self._cryptographic_parameters = None
        elif isinstance(value, CryptographicParameters):
            self._cryptographic_parameters = value
        else:
            raise TypeError(
                "cryptographic parameters must be a CryptographicParameters "
                "struct"
            )

    @property
    def initialization_vector(self):
        if self._initialization_vector:
            return self._initialization_vector.value
        else:
            return None

    @initialization_vector.setter
    def initialization_vector(self, value):
        if value is None:
            self._initialization_vector = None
        elif isinstance(value, bytes):
            self._initialization_vector = ByteString(
                value=value,
                tag=enums.Tags.INITIALIZATION_VECTOR
            )
        else:
            raise TypeError("initialization vector must be bytes")

    @property
    def derivation_data(self):
        if self._derivation_data:
            return self._derivation_data.value
        else:
            return None

    @derivation_data.setter
    def derivation_data(self, value):
        if value is None:
            self._derivation_data = None
        elif isinstance(value, bytes):
            self._derivation_data = ByteString(
                value=value,
                tag=enums.Tags.DERIVATION_DATA
            )
        else:
            raise TypeError("derivation data must be bytes")

    @property
    def salt(self):
        if self._salt:
            return self._salt.value
        else:
            return None

    @salt.setter
    def salt(self, value):
        if value is None:
            self._salt = None
        elif isinstance(value, bytes):
            self._salt = ByteString(
                value=value,
                tag=enums.Tags.SALT
            )
        else:
            raise TypeError("salt must be bytes")

    @property
    def iteration_count(self):
        if self._iteration_count:
            return self._iteration_count.value
        else:
            return None

    @iteration_count.setter
    def iteration_count(self, value):
        if value is None:
            self._iteration_count = None
        elif isinstance(value, int):
            self._iteration_count = Integer(
                value=value,
                tag=Tags.ITERATION_COUNT
            )
        else:
            raise TypeError("iteration count must be an integer")

    def read(self, input_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Read the data encoding the DerivationParameters struct and decode it
        into its constituent parts.

        Args:
            input_stream (stream): A data stream containing encoded object
                data, supporting a read method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be decoded. Optional,
                defaults to KMIP 1.0.
        """
        super(DerivationParameters, self).read(
            input_stream,
            kmip_version=kmip_version
        )
        local_stream = BytearrayStream(input_stream.read(self.length))

        if self.is_tag_next(
                enums.Tags.CRYPTOGRAPHIC_PARAMETERS,
                local_stream
        ):
            self._cryptographic_parameters = CryptographicParameters()
            self._cryptographic_parameters.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.INITIALIZATION_VECTOR, local_stream):
            self._initialization_vector = ByteString(
                tag=enums.Tags.INITIALIZATION_VECTOR
            )
            self._initialization_vector.read(
                local_stream,
                kmip_version=kmip_version
            )

        if self.is_tag_next(enums.Tags.DERIVATION_DATA, local_stream):
            self._derivation_data = ByteString(tag=enums.Tags.DERIVATION_DATA)
            self._derivation_data.read(local_stream, kmip_version=kmip_version)

        if self.is_tag_next(enums.Tags.SALT, local_stream):
            self._salt = ByteString(tag=enums.Tags.SALT)
            self._salt.read(local_stream, kmip_version=kmip_version)

        if self.is_tag_next(Tags.ITERATION_COUNT, local_stream):
            self._iteration_count = Integer(tag=Tags.ITERATION_COUNT)
            self._iteration_count.read(local_stream, kmip_version=kmip_version)

        self.is_oversized(local_stream)

    def write(self, output_stream, kmip_version=enums.KMIPVersion.KMIP_1_0):
        """
        Write the data encoding the DerivationParameters struct to a stream.

        Args:
            output_stream (stream): A data stream in which to encode object
                data, supporting a write method; usually a BytearrayStream
                object.
            kmip_version (KMIPVersion): An enumeration defining the KMIP
                version with which the object will be encoded. Optional,
                defaults to KMIP 1.0.
        """
        local_stream = BytearrayStream()

        if self._cryptographic_parameters:
            self._cryptographic_parameters.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._initialization_vector:
            self._initialization_vector.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._derivation_data:
            self._derivation_data.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._salt:
            self._salt.write(
                local_stream,
                kmip_version=kmip_version
            )
        if self._iteration_count:
            self._iteration_count.write(
                local_stream,
                kmip_version=kmip_version
            )

        self.length = local_stream.length()
        super(DerivationParameters, self).write(
            output_stream,
            kmip_version=kmip_version
        )
        output_stream.write(local_stream.buffer)

    def __eq__(self, other):
        if isinstance(other, DerivationParameters):
            if self.cryptographic_parameters != other.cryptographic_parameters:
                return False
            elif self.initialization_vector != other.initialization_vector:
                return False
            elif self.derivation_data != other.derivation_data:
                return False
            elif self.salt != other.salt:
                return False
            elif self.iteration_count != other.iteration_count:
                return False
            else:
                return True

    def __ne__(self, other):
        if isinstance(other, DerivationParameters):
            return not self == other
        else:
            return NotImplemented

    def __repr__(self):
        args = ", ".join([
            "cryptographic_parameters={0}".format(
                repr(self.cryptographic_parameters)
            ),
            "initialization_vector={0}".format(self.initialization_vector),
            "derivation_data={0}".format(self.derivation_data),
            "salt={0}".format(self.salt),
            "iteration_count={0}".format(
                self.iteration_count
            )
        ])
        return "DerivationParameters({0})".format(args)

    def __str__(self):
        return str({
            'cryptographic_parameters': self.cryptographic_parameters,
            'initialization_vector': self.initialization_vector,
            'derivation_data': self.derivation_data,
            'salt': self.salt,
            'iteration_count': self.iteration_count
        })
