# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

from abc import abstractmethod
from sqlalchemy import Column, event, ForeignKey, Integer, String, VARBINARY
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm import relationship

import binascii
import six

from kmip.core import enums
from kmip.pie import sqltypes as sql


class ManagedObject(sql.Base):
    """
    The abstract base class of the simplified KMIP object hierarchy.

    A ManagedObject is a core KMIP object that is the subject of key
    management operations. It contains various attributes that are common to
    all types of ManagedObjects, including keys, certificates, and various
    types of secret or sensitive data.

    For more information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        value: The value of the ManagedObject. Type varies, usually bytes.
        unique_identifier: The string ID of the ManagedObject.
        names: A list of names associated with the ManagedObject.
        object_type: An enumeration associated with the type of ManagedObject.
    """

    __tablename__ = 'managed_objects'
    unique_identifier = Column('uid', Integer, primary_key=True)
    _object_type = Column('object_type', sql.EnumType(enums.ObjectType))
    _class_type = Column('class_type', String(50))
    value = Column('value', VARBINARY(1024))
    name_index = Column(Integer, default=0)
    _names = relationship('ManagedObjectName', back_populates='mo',
                          cascade='all, delete-orphan')
    names = association_proxy('_names', 'name')
    operation_policy_name = Column(
        'operation_policy_name',
        String(50),
        default='default'
    )
    _owner = Column('owner', String(50), default=None)

    __mapper_args__ = {
        'polymorphic_identity': 'ManagedObject',
        'polymorphic_on': _class_type
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    @abstractmethod
    def __init__(self):
        """
        Create a ManagedObject.
        """
        self.value = None

        self.unique_identifier = None
        self.name_index = 0
        self.names = list()
        self.operation_policy_name = None
        self._object_type = None
        self._owner = None

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._application_specific_informations = list()
        self._contact_information = None
        self._object_groups = list()

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._archive_date = None
        self._initial_date = None
        self._last_change_date = None

    @property
    def object_type(self):
        """
        Accessor and property definition for the object type attribute.

        Returns:
            ObjectType: An ObjectType enumeration that corresponds to the
                class of the object.
        """
        return self._object_type

    @object_type.setter
    def object_type(self, value):
        """
        Set blocker for the object type attribute.

        Raises:
            AttributeError: Always raised to block setting of attribute.
        """
        raise AttributeError("object type cannot be set")

    @abstractmethod
    def validate(self):
        """
        Verify that the contents of the ManagedObject are valid.
        """
        pass

    @abstractmethod
    def __repr__(self):
        pass

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __ne__(self, other):
        pass


class CryptographicObject(ManagedObject):
    """
    The abstract base class of all ManagedObjects related to cryptography.

    A CryptographicObject is a core KMIP object that is the subject of key
    management operations. It contains various attributes that are common to
    all types of CryptographicObjects, including keys and certificates.

    For more information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        cryptographic_usage_masks: A list of usage mask enumerations
            describing how the CryptographicObject will be used.
    """

    __tablename__ = 'crypto_objects'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('managed_objects.uid'),
                               primary_key=True)
    cryptographic_usage_masks = Column('cryptographic_usage_mask',
                                       sql.UsageMaskType)
    state = Column('state', sql.EnumType(enums.State))
    __mapper_args__ = {
        'polymorphic_identity': 'CryptographicObject'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    @abstractmethod
    def __init__(self):
        """
        Create a CryptographicObject.
        """

        super(CryptographicObject, self).__init__()

        self.cryptographic_usage_masks = list()
        self.state = enums.State.PRE_ACTIVE

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._digests = list()

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._activation_date = None
        self._compromise_date = None
        self._compromise_occurrence_date = None
        self._deactivation_date = None
        self._destroy_date = None
        self._fresh = None
        self._lease_time = None
        self._links = list()
        self._revocation_reason = None


class Key(CryptographicObject):
    """
    The abstract base class of all ManagedObjects that are cryptographic keys.

    A Key is a core KMIP object that is the subject of key management
    operations. It contains various attributes that are common to all types of
    Keys, including symmetric and asymmetric keys.

    For more information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        cryptographic_algorithm: A CryptographicAlgorithm enumeration defining
            the algorithm the key should be used with.
        cryptographic_length: An int defining the length of the key in bits.
        key_format_type: A KeyFormatType enumeration defining the format of
            the key value.
    """

    __tablename__ = 'keys'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('crypto_objects.uid'),
                               primary_key=True)
    cryptographic_algorithm = Column(
        'cryptographic_algorithm', sql.EnumType(enums.CryptographicAlgorithm))
    cryptographic_length = Column('cryptographic_length', Integer)
    key_format_type = Column(
        'key_format_type', sql.EnumType(enums.KeyFormatType))

    __mapper_args__ = {
        'polymorphic_identity': 'Key'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    @abstractmethod
    def __init__(self):
        """
        Create a Key object.
        """
        super(Key, self).__init__()

        self.cryptographic_algorithm = None
        self.cryptographic_length = None
        self.key_format_type = None

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._cryptographic_parameters = list()

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._usage_limits = None


class SymmetricKey(Key):
    """
    The SymmetricKey class of the simplified KMIP object hierarchy.

    A SymmetricKey is a core KMIP object that is the subject of key
    management operations. For more information, see Section 2.2 of the KMIP
    1.1 specification.

    Attributes:
        cryptographic_algorithm: The type of algorithm for the SymmetricKey.
        cryptographic_length: The length in bits of the SymmetricKey value.
        value: The bytes of the SymmetricKey.
        key_format_type: The format of the key value.
        cryptographic_usage_masks: The list of usage mask flags for
            SymmetricKey application.
        names: The string names of the SymmetricKey.
    """

    __tablename__ = 'symmetric_keys'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('keys.uid'),
                               primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'SymmetricKey'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    def __init__(self, algorithm, length, value, masks=None,
                 name='Symmetric Key'):
        """
        Create a SymmetricKey.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration identifying the
                type of algorithm for the key.
            length(int): The length in bits of the key.
            value(bytes): The bytes representing the key.
            masks(list): A list of CryptographicUsageMask enumerations defining
                how the key will be used. Optional, defaults to None.
            name(string): The string name of the key. Optional, defaults to
                'Symmetric Key'.
        """
        super(SymmetricKey, self).__init__()

        self._object_type = enums.ObjectType.SYMMETRIC_KEY
        self.key_format_type = enums.KeyFormatType.RAW

        self.value = value
        self.cryptographic_algorithm = algorithm
        self.cryptographic_length = length
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks.extend(masks)

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._process_start_date = None
        self._protect_stop_date = None

        self.validate()

    def validate(self):
        """
        Verify that the contents of the SymmetricKey object are valid.

        Raises:
            TypeError: if the types of any SymmetricKey attributes are invalid
            ValueError: if the key length and key value length do not match
        """
        if not isinstance(self.value, bytes):
            raise TypeError("key value must be bytes")
        elif not isinstance(self.cryptographic_algorithm,
                            enums.CryptographicAlgorithm):
            raise TypeError("key algorithm must be a CryptographicAlgorithm "
                            "enumeration")
        elif not isinstance(self.cryptographic_length, six.integer_types):
            raise TypeError("key length must be an integer")

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, enums.CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "key mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

        if (len(self.value) * 8) != self.cryptographic_length:
            msg = "key length ({0}) not equal to key value length ({1})"
            msg = msg.format(self.cryptographic_length, len(self.value) * 8)
            raise ValueError(msg)

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))

        return "SymmetricKey({0}, {1}, {2})".format(algorithm, length, value)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, SymmetricKey):
            if self.value != other.value:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SymmetricKey):
            return not (self == other)
        else:
            return NotImplemented


event.listen(SymmetricKey._names, 'append',
             sql.attribute_append_factory("name_index"), retval=False)


class PublicKey(Key):
    """
    The PublicKey class of the simplified KMIP object hierarchy.

    A PublicKey is a core KMIP object that is the subject of key management
    operations. For more information, see Section 2.2 of the KMIP 1.1
    specification.

    Attributes:
        cryptographic_algorithm: The type of algorithm for the PublicKey.
        cryptographic_length: The length in bits of the PublicKey.
        value: The bytes of the PublicKey.
        key_format_type: The format of the key value.
        cryptographic_usage_masks: The list of usage mask flags for PublicKey
            application.
        names: The list of string names of the PublicKey.
    """

    __tablename__ = 'public_keys'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('keys.uid'),
                               primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'PublicKey'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    def __init__(self, algorithm, length, value,
                 format_type=enums.KeyFormatType.X_509, masks=None,
                 name='Public Key'):
        """
        Create a PublicKey.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration identifying the
                type of algorithm for the key.
            length(int): The length in bits of the key.
            value(bytes): The bytes representing the key.
            format_type(KeyFormatType): An enumeration defining the format of
                the key value. Optional, defaults to enums.KeyFormatType.X_509.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the key will be used. Optional, defaults to None.
            name(string): The string name of the key. Optional, defaults to
                'Public Key'.
        """
        super(PublicKey, self).__init__()

        self._object_type = enums.ObjectType.PUBLIC_KEY
        self._valid_formats = [
            enums.KeyFormatType.RAW,
            enums.KeyFormatType.X_509,
            enums.KeyFormatType.PKCS_1]

        self.value = value
        self.cryptographic_algorithm = algorithm
        self.cryptographic_length = length
        self.key_format_type = format_type
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks = masks

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._cryptographic_domain_parameters = list()

        self.validate()

    def validate(self):
        """
        Verify that the contents of the PublicKey object are valid.

        Raises:
            TypeError: if the types of any PublicKey attributes are invalid.
        """
        if not isinstance(self.value, bytes):
            raise TypeError("key value must be bytes")
        elif not isinstance(self.cryptographic_algorithm,
                            enums.CryptographicAlgorithm):
            raise TypeError("key algorithm must be a CryptographicAlgorithm "
                            "enumeration")
        elif not isinstance(self.cryptographic_length, six.integer_types):
            raise TypeError("key length must be an integer")
        elif not isinstance(self.key_format_type, enums.KeyFormatType):
            raise TypeError("key format type must be a KeyFormatType "
                            "enumeration")
        elif self.key_format_type not in self._valid_formats:
            raise ValueError("key format type must be one of {0}".format(
                self._valid_formats))

        # TODO (peter-hamilton) Verify that the key bytes match the key format

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, enums.CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "key mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        format_type = "format_type={0}".format(self.key_format_type)

        return "PublicKey({0}, {1}, {2}, {3})".format(
            algorithm, length, value, format_type)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            if self.value != other.value:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, PublicKey):
            return not (self == other)
        else:
            return NotImplemented


event.listen(PublicKey._names, 'append',
             sql.attribute_append_factory("name_index"), retval=False)


class PrivateKey(Key):
    """
    The PrivateKey class of the simplified KMIP object hierarchy.

    A PrivateKey is a core KMIP object that is the subject of key management
    operations. For more information, see Section 2.2 of the KMIP 1.1
    specification.

    Attributes:
        cryptographic_algorithm: The type of algorithm for the PrivateKey.
        cryptographic_length: The length in bits of the PrivateKey.
        value: The bytes of the PrivateKey.
        key_format_type: The format of the key value.
        cryptographic_usage_masks: The list of usage mask flags for PrivateKey
            application. Optional, defaults to None.
        names: The list of string names of the PrivateKey. Optional, defaults
            to 'Private Key'.
    """

    __tablename__ = 'private_keys'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('keys.uid'),
                               primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'PrivateKey'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    def __init__(self, algorithm, length, value, format_type, masks=None,
                 name='Private Key'):
        """
        Create a PrivateKey.

        Args:
            algorithm(CryptographicAlgorithm): An enumeration identifying the
                type of algorithm for the key.
            length(int): The length in bits of the key.
            value(bytes): The bytes representing the key.
            format_type(KeyFormatType): An enumeration defining the format of
                the key value.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the key will be used.
            name(string): The string name of the key.
        """
        super(PrivateKey, self).__init__()

        self._object_type = enums.ObjectType.PRIVATE_KEY
        self._valid_formats = [
            enums.KeyFormatType.RAW,
            enums.KeyFormatType.PKCS_1,
            enums.KeyFormatType.PKCS_8]

        self.value = value
        self.cryptographic_algorithm = algorithm
        self.cryptographic_length = length
        self.key_format_type = format_type
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks = masks

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._cryptographic_domain_parameters = list()

        self.validate()

    def validate(self):
        """
        Verify that the contents of the PrivateKey object are valid.

        Raises:
            TypeError: if the types of any PrivateKey attributes are invalid.
        """
        if not isinstance(self.value, bytes):
            raise TypeError("key value must be bytes")
        elif not isinstance(self.cryptographic_algorithm,
                            enums.CryptographicAlgorithm):
            raise TypeError("key algorithm must be a CryptographicAlgorithm "
                            "enumeration")
        elif not isinstance(self.cryptographic_length, six.integer_types):
            raise TypeError("key length must be an integer")
        elif not isinstance(self.key_format_type, enums.KeyFormatType):
            raise TypeError("key format type must be a KeyFormatType "
                            "enumeration")
        elif self.key_format_type not in self._valid_formats:
            raise ValueError("key format type must be one of {0}".format(
                self._valid_formats))

        # TODO (peter-hamilton) Verify that the key bytes match the key format

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, enums.CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "key mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        format_type = "format_type={0}".format(self.key_format_type)

        return "PrivateKey({0}, {1}, {2}, {3})".format(
            algorithm, length, value, format_type)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            if self.value != other.value:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, PrivateKey):
            return not (self == other)
        else:
            return NotImplemented


event.listen(PrivateKey._names, 'append',
             sql.attribute_append_factory("name_index"), retval=False)


class Certificate(CryptographicObject):
    """
    The Certificate class of the simplified KMIP object hierarchy.

    A Certificate is a core KMIP object that is the subject of key management
    operations. For more information, see Section 2.2 of the KMIP 1.1
    specification.

    Attributes:
        certificate_type: The type of the Certificate.
        value: The bytes of the Certificate.
        cryptographic_usage_masks: The list of usage mask flags for
            Certificate application.
        names: The list of string names of the Certificate.
    """

    __tablename__ = 'certificates'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('crypto_objects.uid'),
                               primary_key=True)
    certificate_type = Column(
        'certificate_type', sql.EnumType(enums.CertificateTypeEnum))

    __mapper_args__ = {
        'polymorphic_identity': 'Certificate'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    @abstractmethod
    def __init__(self, certificate_type, value, masks=None,
                 name='Certificate'):
        """
        Create a Certificate.

        Args:
            certificate_type(CertificateType): An enumeration defining the
                type of the certificate.
            value(bytes): The bytes representing the certificate.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the certificate will be used.
            name(string): The string name of the certificate.
        """
        super(Certificate, self).__init__()

        self._object_type = enums.ObjectType.CERTIFICATE

        self.value = value
        self.certificate_type = certificate_type
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks = masks

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._cryptographic_algorithm = None
        self._cryptographic_length = None
        self._certificate_length = None

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._cryptographic_parameters = list()
        self._digital_signature_algorithm = list()

        self.validate()

    def validate(self):
        """
        Verify that the contents of the Certificate object are valid.

        Raises:
            TypeError: if the types of any Certificate attributes are invalid.
        """
        if not isinstance(self.value, bytes):
            raise TypeError("certificate value must be bytes")
        elif not isinstance(self.certificate_type,
                            enums.CertificateTypeEnum):
            raise TypeError("certificate type must be a CertificateTypeEnum "
                            "enumeration")

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, enums.CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "certificate mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("certificate name {0} must be a string".format(
                    position))

    def __str__(self):
        return str(binascii.hexlify(self.value))


class X509Certificate(Certificate):
    """
    The X509Certificate class of the simplified KMIP object hierarchy.

    An X509Certificate is a core KMIP object that is the subject of key
    management operations. For more information, see Section 2.2 of the KMIP
    1.1 specification.

    Attributes:
        value: The bytes of the Certificate.
        cryptographic_usage_masks: The list of usage mask flags for
            Certificate application.
        names: The list of string names of the Certificate.
    """

    __tablename__ = 'x509_certificates'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('certificates.uid'),
                               primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'Certificate'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    def __init__(self, value, masks=None, name='X.509 Certificate'):
        """
        Create an X509Certificate.

        Args:
            value(bytes): The bytes representing the certificate.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the certificate will be used.
            name(string): The string name of the certificate.
        """
        super(X509Certificate, self).__init__(
            enums.CertificateTypeEnum.X_509, value, masks, name)

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._x509_certificate_identifier = None
        self._x509_certificate_subject = None
        self._x509_certificate_issuer = None

        self.validate()

    def __repr__(self):
        certificate_type = "certificate_type={0}".format(self.certificate_type)
        value = "value={0}".format(binascii.hexlify(self.value))

        return "X509Certificate({0}, {1})".format(certificate_type, value)

    def __eq__(self, other):
        if isinstance(other, X509Certificate):
            if self.value != other.value:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, X509Certificate):
            return not (self == other)
        else:
            return NotImplemented


event.listen(X509Certificate._names, 'append',
             sql.attribute_append_factory("name_index"), retval=False)


class SecretData(CryptographicObject):
    """
    The SecretData class of the simplified KMIP object hierarchy.

    SecretData is one of several CryptographicObjects and is one of the core
    KMIP objects that are the subject of key management operations. For more
    information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        cryptographic_usage_masks: A list of usage mask enumerations
            describing how the CryptographicObject will be used.
        data_type: The type of the secret value.
    """

    __tablename__ = 'secret_data_objects'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('crypto_objects.uid'),
                               primary_key=True)
    data_type = Column('data_type', sql.EnumType(enums.SecretDataType))
    __mapper_args__ = {
        'polymorphic_identity': 'SecretData'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    def __init__(self, value, data_type, masks=None, name='Secret Data'):
        """
        Create a SecretData object.

        Args:
            value(bytes): The bytes representing secret data.
            data_type(SecretDataType): An enumeration defining the type of the
                secret value.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the key will be used.
            name(string): The string name of the key.
        """
        super(SecretData, self).__init__()

        self._object_type = enums.ObjectType.SECRET_DATA

        self.value = value
        self.data_type = data_type
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks = masks

        # All remaining attributes are not considered part of the public API
        # and are subject to change.

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core

        self.validate()

    def validate(self):
        """
        Verify that the contents of the SecretData object are valid.

        Raises:
            TypeError: if the types of any SecretData attributes are invalid.
        """
        if not isinstance(self.value, bytes):
            raise TypeError("secret value must be bytes")
        elif not isinstance(self.data_type, enums.SecretDataType):
            raise TypeError("secret data type must be a SecretDataType "
                            "enumeration")

        mask_count = len(self.cryptographic_usage_masks)
        for i in range(mask_count):
            mask = self.cryptographic_usage_masks[i]
            if not isinstance(mask, enums.CryptographicUsageMask):
                position = "({0} in list)".format(i)
                raise TypeError(
                    "secret data mask {0} must be a CryptographicUsageMask "
                    "enumeration".format(position))

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("secret data name {0} must be a string".format(
                    position))

    def __repr__(self):
        value = "value={0}".format(binascii.hexlify(self.value))
        data_type = "data_type={0}".format(self.data_type)

        return "SecretData({0}, {1})".format(value, data_type)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, SecretData):
            if self.value != other.value:
                return False
            elif self.data_type != other.data_type:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SecretData):
            return not (self == other)
        else:
            return NotImplemented


event.listen(SecretData._names, 'append',
             sql.attribute_append_factory("name_index"), retval=False)


class OpaqueObject(ManagedObject):
    """
    The OpaqueObject class of the simplified KMIP object hierarchy.

    OpaqueObject is one of several ManagedObjects and is one of the core KMIP
    objects that are the subject of key management operations. For more
    information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        opaque_type: The type of the opaque value.
    """

    __tablename__ = 'opaque_objects'
    unique_identifier = Column('uid', Integer,
                               ForeignKey('managed_objects.uid'),
                               primary_key=True)
    opaque_type = Column('opaque_type', sql.EnumType(enums.OpaqueDataType))
    __mapper_args__ = {
        'polymorphic_identity': 'OpaqueData'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    def __init__(self, value, opaque_type, name='Opaque Object'):
        """
        Create a OpaqueObject.

        Args:
            value(bytes): The bytes representing opaque data.
            opaque_type(OpaqueDataType): An enumeration defining the type of
                the opaque value.
            name(string): The string name of the opaque object.
        """
        super(OpaqueObject, self).__init__()

        self._object_type = enums.ObjectType.OPAQUE_DATA

        self.value = value
        self.opaque_type = opaque_type
        self.names.append(name)

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._digest = None
        self._revocation_reason = None

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._destroy_date = None
        self._compromise_occurrence_date = None
        self._compromise_date = None

        self.validate()

    def validate(self):
        """
        Verify that the contents of the OpaqueObject are valid.

        Raises:
            TypeError: if the types of any OpaqueObject attributes are invalid.
        """
        if not isinstance(self.value, bytes):
            raise TypeError("opaque value must be bytes")
        elif not isinstance(self.opaque_type, enums.OpaqueDataType):
            raise TypeError("opaque data type must be an OpaqueDataType "
                            "enumeration")

        name_count = len(self.names)
        for i in range(name_count):
            name = self.names[i]
            if not isinstance(name, six.string_types):
                position = "({0} in list)".format(i)
                raise TypeError("opaque data name {0} must be a string".format(
                    position))

    def __repr__(self):
        value = "value={0}".format(binascii.hexlify(self.value))
        opaque_type = "opaque_type={0}".format(self.opaque_type)

        return "OpaqueObject({0}, {1})".format(value, opaque_type)

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, OpaqueObject):
            if self.value != other.value:
                return False
            elif self.opaque_type != other.opaque_type:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, OpaqueObject):
            return not (self == other)
        else:
            return NotImplemented


event.listen(OpaqueObject._names, 'append',
             sql.attribute_append_factory("name_index"), retval=False)
