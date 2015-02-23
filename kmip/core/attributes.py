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

from kmip.core.enums import Tags

from kmip.core.errors import ErrorStrings

from kmip.core.primitives import Struct
from kmip.core.primitives import Integer
from kmip.core.primitives import Enumeration
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
            super(self.__class__, self).__init__(value, Tags.NAME_VALUE)

    class NameType(Enumeration):

        ENUM_TYPE = enums.NameType

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value, Tags.NAME_TYPE)

    def __init__(self, name_value=None, name_type=None):
        super(self.__class__, self).__init__(tag=Tags.NAME)
        self.name_value = name_value
        self.name_type = name_type
        self.validate()

    def read(self, istream):
        super(self.__class__, self).read(istream)
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
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        name = self.__class__.__name__
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


# 3.3
class ObjectType(Enumeration):

    ENUM_TYPE = enums.ObjectType

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value, Tags.OBJECT_TYPE)


# 3.4
class CryptographicAlgorithm(Enumeration):

    ENUM_TYPE = enums.CryptographicAlgorithm

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value,
                                             Tags.CRYPTOGRAPHIC_ALGORITHM)


# 3.5
class CryptographicLength(Integer):

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value,
                                             Tags.CRYPTOGRAPHIC_LENGTH)


# 3.6
class CryptographicParameters(Struct):

    class BlockCipherMode(Enumeration):
        ENUM_TYPE = enums.BlockCipherMode

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.BLOCK_CIPHER_MODE)

    class PaddingMethod(Enumeration):
        ENUM_TYPE = enums.PaddingMethod

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.PADDING_METHOD)

    class HashingAlgorithm(Enumeration):
        ENUM_TYPE = enums.HashingAlgorithm

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.HASHING_ALGORITHM)

    class KeyRoleType(Enumeration):
        ENUM_TYPE = enums.KeyRoleType

        def __init__(self, value=None):
            super(self.__class__, self).__init__(value,
                                                 Tags.KEY_ROLE_TYPE)

    def __init__(self,
                 block_cipher_mode=None,
                 padding_method=None,
                 hashing_algorithm=None,
                 key_role_type=None):
        super(self.__class__, self).__init__(tag=Tags.CRYPTOGRAPHIC_PARAMETERS)
        self.block_cipher_mode = block_cipher_mode
        self.padding_method = padding_method
        self.hashing_algorithm = hashing_algorithm
        self.key_role_type = key_role_type

    def read(self, istream):
        super(self.__class__, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        if self.is_tag_next(Tags.BLOCK_CIPHER_MODE, tstream):
            self.block_cipher_mode = CryptographicParameters.BlockCipherMode()
            self.block_cipher_mode.read(tstream)

        if self.is_tag_next(Tags.PADDING_METHOD, tstream):
            self.padding_method = CryptographicParameters.PaddingMethod()
            self.padding_method.read(tstream)

        if self.is_tag_next(Tags.HASHING_ALGORITHM, tstream):
            self.hashing_algorithm = CryptographicParameters.HashingAlgorithm()
            self.hashing_algorithm.read(tstream)

        if self.is_tag_next(Tags.KEY_ROLE_TYPE, tstream):
            self.key_role_type = CryptographicParameters.KeyRoleType()
            self.key_role_type.read(tstream)

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

        # Write the length and value of the request payload
        self.length = tstream.length()
        super(self.__class__, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass


# 3.8
class CertificateType(Enumeration):
    ENUM_TYPE = enums.CertificateType

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value,
                                             Tags.CERTIFICATE_TYPE)


# 3.18
class OperationPolicyName(TextString):

    def __init__(self, value=None):
        super(OperationPolicyName, self).__init__(
            value, Tags.OPERATION_POLICY_NAME)


# 3.19
class CryptographicUsageMask(Integer):

    ENUM_TYPE = enums.CryptographicUsageMask

    def __init__(self, value=None):
        super(self.__class__, self).__init__(value,
                                             Tags.CRYPTOGRAPHIC_USAGE_MASK)


# 3.33
class ObjectGroup(TextString):

    def __init__(self, value=None):
        super(self.__class__,
              self).__init__(value, Tags.OBJECT_GROUP)


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
        super(self.__class__,
              self).__init__(value, Tags.CONTACT_INFORMATION)


# 3.39
# TODO (peter-hamilton) A CustomAttribute TextString is not sufficient to
# TODO (peter-hamilton) cover all potential custom attributes. This is a
# TODO (peter-hamilton) temporary stopgap.
class CustomAttribute(TextString):

    def __init__(self, value=None):
        super(self.__class__,
              self).__init__(value, Tags.ATTRIBUTE_VALUE)
