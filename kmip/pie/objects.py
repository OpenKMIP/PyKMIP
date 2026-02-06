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
import sqlalchemy
from sqlalchemy import Column, event, ForeignKey, Integer, String, VARBINARY
from sqlalchemy import Boolean
from sqlalchemy.ext.associationproxy import association_proxy

import binascii

from kmip.core import enums
from kmip.pie import sqltypes as sql

app_specific_info_map = sqlalchemy.Table(
    "app_specific_info_map",
    sql.Base.metadata,
    sqlalchemy.Column(
        "managed_object_id",
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey(
            "managed_objects.uid",
            ondelete="CASCADE"
        )
    ),
    sqlalchemy.Column(
        "app_specific_info_id",
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey(
            "app_specific_info.id",
            ondelete="CASCADE"
        )
    )
)

object_group_map = sqlalchemy.Table(
    "object_group_map",
    sql.Base.metadata,
    sqlalchemy.Column(
        "managed_object_id",
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey(
            "managed_objects.uid",
            ondelete="CASCADE"
        )
    ),
    sqlalchemy.Column(
        "object_group_id",
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey(
            "object_groups.id",
            ondelete="CASCADE"
        )
    )
)

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
    _names = sqlalchemy.orm.relationship(
        "ManagedObjectName",
        back_populates="mo",
        cascade="all, delete-orphan",
        order_by="ManagedObjectName.id"
    )
    names = association_proxy('_names', 'name')
    operation_policy_name = Column(
        'operation_policy_name',
        String(50),
        default='default'
    )
    sensitive = Column("sensitive", Boolean, default=False)
    initial_date = Column(Integer, default=0)
    _owner = Column('owner', String(50), default=None)

    app_specific_info = sqlalchemy.orm.relationship(
        "ApplicationSpecificInformation",
        secondary=app_specific_info_map,
        back_populates="managed_objects",
        order_by="ApplicationSpecificInformation.id",
        passive_deletes=True
    )
    object_groups = sqlalchemy.orm.relationship(
        "ObjectGroup",
        secondary=object_group_map,
        back_populates="managed_objects",
        order_by="ObjectGroup.id",
        passive_deletes=True
    )

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
        self.initial_date = 0
        self.sensitive = False
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
        key_wrapping_data: A dictionary containing key wrapping data
            settings, describing how the key value has been wrapped.
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

    # Key wrapping data fields
    _kdw_wrapping_method = Column(
        '_kdw_wrapping_method',
        sql.EnumType(enums.WrappingMethod),
        default=None
    )
    _kdw_eki_unique_identifier = Column(
        '_kdw_eki_unique_identifier',
        String,
        default=None
    )
    _kdw_eki_cp_block_cipher_mode = Column(
        '_kdw_eki_cp_block_cipher_mode',
        sql.EnumType(enums.BlockCipherMode),
        default=None
    )
    _kdw_eki_cp_padding_method = Column(
        '_kdw_eki_cp_padding_method',
        sql.EnumType(enums.PaddingMethod),
        default=None
    )
    _kdw_eki_cp_hashing_algorithm = Column(
        '_kdw_eki_cp_hashing_algorithm',
        sql.EnumType(enums.HashingAlgorithm),
        default=None
    )
    _kdw_eki_cp_key_role_type = Column(
        '_kdw_eki_cp_key_role_type',
        sql.EnumType(enums.KeyRoleType),
        default=None
    )
    _kdw_eki_cp_digital_signature_algorithm = Column(
        '_kdw_eki_cp_digital_signature_algorithm',
        sql.EnumType(enums.DigitalSignatureAlgorithm),
        default=None
    )
    _kdw_eki_cp_cryptographic_algorithm = Column(
        '_kdw_eki_cp_cryptographic_algorithm',
        sql.EnumType(enums.CryptographicAlgorithm),
        default=None
    )
    _kdw_eki_cp_random_iv = Column(
        '_kdw_eki_cp_random_iv',
        Boolean,
        default=None
    )
    _kdw_eki_cp_iv_length = Column(
        '_kdw_eki_cp_iv_length',
        Integer,
        default=None
    )
    _kdw_eki_cp_tag_length = Column(
        '_kdw_eki_cp_tag_length',
        Integer,
        default=None
    )
    _kdw_eki_cp_fixed_field_length = Column(
        '_kdw_eki_cp_fixed_field_length',
        Integer,
        default=None
    )
    _kdw_eki_cp_invocation_field_length = Column(
        '_kdw_eki_cp_invocation_field_length',
        Integer
    )
    _kdw_eki_cp_counter_length = Column(
        '_kdw_eki_cp_counter_length',
        Integer,
        default=None
    )
    _kdw_eki_cp_initial_counter_value = Column(
        '_kdw_eki_cp_initial_counter_value',
        Integer,
        default=None
    )
    _kdw_mski_unique_identifier = Column(
        '_kdw_mski_unique_identifier',
        String,
        default=None
    )
    _kdw_mski_cp_block_cipher_mode = Column(
        '_kdw_mski_cp_block_cipher_mode',
        sql.EnumType(enums.BlockCipherMode),
        default=None
    )
    _kdw_mski_cp_padding_method = Column(
        '_kdw_mski_cp_padding_method',
        sql.EnumType(enums.PaddingMethod),
        default=None
    )
    _kdw_mski_cp_hashing_algorithm = Column(
        '_kdw_mski_cp_hashing_algorithm',
        sql.EnumType(enums.HashingAlgorithm),
        default=None
    )
    _kdw_mski_cp_key_role_type = Column(
        '_kdw_mski_cp_key_role_type',
        sql.EnumType(enums.KeyRoleType),
        default=None
    )
    _kdw_mski_cp_digital_signature_algorithm = Column(
        '_kdw_mski_cp_digital_signature_algorithm',
        sql.EnumType(enums.DigitalSignatureAlgorithm),
        default=None
    )
    _kdw_mski_cp_cryptographic_algorithm = Column(
        '_kdw_mski_cp_cryptographic_algorithm',
        sql.EnumType(enums.CryptographicAlgorithm),
        default=None
    )
    _kdw_mski_cp_random_iv = Column(
        '_kdw_mski_cp_random_iv',
        Boolean,
        default=None
    )
    _kdw_mski_cp_iv_length = Column(
        '_kdw_mski_cp_iv_length',
        Integer,
        default=None
    )
    _kdw_mski_cp_tag_length = Column(
        '_kdw_mski_cp_tag_length',
        Integer,
        default=None
    )
    _kdw_mski_cp_fixed_field_length = Column(
        '_kdw_mski_cp_fixed_field_length',
        Integer,
        default=None
    )
    _kdw_mski_cp_invocation_field_length = Column(
        '_kdw_mski_cp_invocation_field_length',
        Integer,
        default=None
    )
    _kdw_mski_cp_counter_length = Column(
        '_kdw_mski_cp_counter_length',
        Integer,
        default=None
    )
    _kdw_mski_cp_initial_counter_value = Column(
        '_kdw_mski_cp_initial_counter_value',
        Integer,
        default=None
    )
    _kdw_mac_signature = Column(
        '_kdw_mac_signature',
        VARBINARY(1024),
        default=None
    )
    _kdw_iv_counter_nonce = Column(
        '_kdw_iv_counter_nonce',
        VARBINARY(1024),
        default=None
    )
    _kdw_encoding_option = Column(
        '_kdw_encoding_option',
        sql.EnumType(enums.EncodingOption),
        default=None
    )

    __mapper_args__ = {
        'polymorphic_identity': 'Key'
    }
    __table_args__ = {
        'sqlite_autoincrement': True
    }

    @abstractmethod
    def __init__(self, key_wrapping_data=None):
        """
        Create a Key object.

        Args:
            key_wrapping_data(dict): A dictionary containing key wrapping data
                settings, describing how the key value has been wrapped.
                Optional, defaults to None.
        """
        super(Key, self).__init__()

        self.cryptographic_algorithm = None
        self.cryptographic_length = None
        self.key_format_type = None
        self.key_wrapping_data = key_wrapping_data

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._cryptographic_parameters = list()

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._usage_limits = None

    @property
    def key_wrapping_data(self):
        """
        Retrieve all of the relevant key wrapping data fields and return them
        as a dictionary.
        """
        key_wrapping_data = {}
        encryption_key_info = {
            'unique_identifier': self._kdw_eki_unique_identifier,
            'cryptographic_parameters': {
                'block_cipher_mode': self._kdw_eki_cp_block_cipher_mode,
                'padding_method': self._kdw_eki_cp_padding_method,
                'hashing_algorithm': self._kdw_eki_cp_hashing_algorithm,
                'key_role_type': self._kdw_eki_cp_key_role_type,
                'digital_signature_algorithm':
                    self._kdw_eki_cp_digital_signature_algorithm,
                'cryptographic_algorithm':
                    self._kdw_eki_cp_cryptographic_algorithm,
                'random_iv': self._kdw_eki_cp_random_iv,
                'iv_length': self._kdw_eki_cp_iv_length,
                'tag_length': self._kdw_eki_cp_tag_length,
                'fixed_field_length': self._kdw_eki_cp_fixed_field_length,
                'invocation_field_length':
                    self._kdw_eki_cp_invocation_field_length,
                'counter_length': self._kdw_eki_cp_counter_length,
                'initial_counter_value':
                    self._kdw_eki_cp_initial_counter_value
            }
        }
        if not any(encryption_key_info['cryptographic_parameters'].values()):
            encryption_key_info['cryptographic_parameters'] = {}
        if not any(encryption_key_info.values()):
            encryption_key_info = {}

        mac_sign_key_info = {
            'unique_identifier': self._kdw_mski_unique_identifier,
            'cryptographic_parameters': {
                'block_cipher_mode': self._kdw_mski_cp_block_cipher_mode,
                'padding_method': self._kdw_mski_cp_padding_method,
                'hashing_algorithm': self._kdw_mski_cp_hashing_algorithm,
                'key_role_type': self._kdw_mski_cp_key_role_type,
                'digital_signature_algorithm':
                    self._kdw_mski_cp_digital_signature_algorithm,
                'cryptographic_algorithm':
                    self._kdw_mski_cp_cryptographic_algorithm,
                'random_iv': self._kdw_mski_cp_random_iv,
                'iv_length': self._kdw_mski_cp_iv_length,
                'tag_length': self._kdw_mski_cp_tag_length,
                'fixed_field_length': self._kdw_mski_cp_fixed_field_length,
                'invocation_field_length':
                    self._kdw_mski_cp_invocation_field_length,
                'counter_length': self._kdw_mski_cp_counter_length,
                'initial_counter_value':
                    self._kdw_mski_cp_initial_counter_value
            }
        }
        if not any(mac_sign_key_info['cryptographic_parameters'].values()):
            mac_sign_key_info['cryptographic_parameters'] = {}
        if not any(mac_sign_key_info.values()):
            mac_sign_key_info = {}

        key_wrapping_data['wrapping_method'] = self._kdw_wrapping_method
        key_wrapping_data['encryption_key_information'] = encryption_key_info
        key_wrapping_data['mac_signature_key_information'] = mac_sign_key_info
        key_wrapping_data['mac_signature'] = self._kdw_mac_signature
        key_wrapping_data['iv_counter_nonce'] = self._kdw_iv_counter_nonce
        key_wrapping_data['encoding_option'] = self._kdw_encoding_option
        if not any(key_wrapping_data.values()):
            key_wrapping_data = {}

        return key_wrapping_data

    @key_wrapping_data.setter
    def key_wrapping_data(self, value):
        """
        Set the key wrapping data attributes using a dictionary.
        """
        if value is None:
            value = {}
        elif not isinstance(value, dict):
            raise TypeError("Key wrapping data must be a dictionary.")

        self._kdw_wrapping_method = value.get('wrapping_method')

        eki = value.get('encryption_key_information')
        if eki is None:
            eki = {}
        self._kdw_eki_unique_identifier = eki.get('unique_identifier')
        eki_cp = eki.get('cryptographic_parameters')
        if eki_cp is None:
            eki_cp = {}
        self._kdw_eki_cp_block_cipher_mode = eki_cp.get('block_cipher_mode')
        self._kdw_eki_cp_padding_method = eki_cp.get('padding_method')
        self._kdw_eki_cp_hashing_algorithm = eki_cp.get('hashing_algorithm')
        self._kdw_eki_cp_key_role_type = eki_cp.get('key_role_type')
        self._kdw_eki_cp_digital_signature_algorithm = \
            eki_cp.get('digital_signature_algorithm')
        self._kdw_eki_cp_cryptographic_algorithm = \
            eki_cp.get('cryptographic_algorithm')
        self._kdw_eki_cp_random_iv = eki_cp.get('random_iv')
        self._kdw_eki_cp_iv_length = eki_cp.get('iv_length')
        self._kdw_eki_cp_tag_length = eki_cp.get('tag_length')
        self._kdw_eki_cp_fixed_field_length = eki_cp.get('fixed_field_length')
        self._kdw_eki_cp_invocation_field_length = \
            eki_cp.get('invocation_field_length')
        self._kdw_eki_cp_counter_length = eki_cp.get('counter_length')
        self._kdw_eki_cp_initial_counter_value = \
            eki_cp.get('initial_counter_value')

        mski = value.get('mac_signature_key_information')
        if mski is None:
            mski = {}
        self._kdw_mski_unique_identifier = mski.get('unique_identifier')
        mski_cp = mski.get('cryptographic_parameters')
        if mski_cp is None:
            mski_cp = {}
        self._kdw_mski_cp_block_cipher_mode = mski_cp.get('block_cipher_mode')
        self._kdw_mski_cp_padding_method = mski_cp.get('padding_method')
        self._kdw_mski_cp_hashing_algorithm = mski_cp.get('hashing_algorithm')
        self._kdw_mski_cp_key_role_type = mski_cp.get('key_role_type')
        self._kdw_mski_cp_digital_signature_algorithm = \
            mski_cp.get('digital_signature_algorithm')
        self._kdw_mski_cp_cryptographic_algorithm = \
            mski_cp.get('cryptographic_algorithm')
        self._kdw_mski_cp_random_iv = mski_cp.get('random_iv')
        self._kdw_mski_cp_iv_length = mski_cp.get('iv_length')
        self._kdw_mski_cp_tag_length = mski_cp.get('tag_length')
        self._kdw_mski_cp_fixed_field_length = \
            mski_cp.get('fixed_field_length')
        self._kdw_mski_cp_invocation_field_length = \
            mski_cp.get('invocation_field_length')
        self._kdw_mski_cp_counter_length = mski_cp.get('counter_length')
        self._kdw_mski_cp_initial_counter_value = \
            mski_cp.get('initial_counter_value')

        self._kdw_mac_signature = value.get('mac_signature')
        self._kdw_iv_counter_nonce = value.get('iv_counter_nonce')
        self._kdw_encoding_option = value.get('encoding_option')

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
        key_wrapping_data: A dictionary containing key wrapping data
            settings, describing how the key value has been wrapped.
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
                 name='Symmetric Key', key_wrapping_data=None,
                 app_specific_info=None):
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
            key_wrapping_data(dict): A dictionary containing key wrapping data
                settings, describing how the key value has been wrapped.
                Optional, defaults to None.
            app_specific_info(list): A list of dictionaries containing
                application_namespace and application_data. Optional, defaults
                to None.
        """
        super(SymmetricKey, self).__init__(
            key_wrapping_data=key_wrapping_data
        )

        self._object_type = enums.ObjectType.SYMMETRIC_KEY
        self.key_format_type = enums.KeyFormatType.RAW

        self.value = value
        self.cryptographic_algorithm = algorithm
        self.cryptographic_length = length
        self.names = [name]

        if masks:
            self.cryptographic_usage_masks.extend(masks)

        if app_specific_info:
            self._application_specific_informations = app_specific_info

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
        elif not isinstance(self.cryptographic_length, int):
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
            if not isinstance(name, str):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

        if not self.key_wrapping_data:
            if (len(self.value) * 8) != self.cryptographic_length:
                msg = "key length ({0}) not equal to key value length ({1})"
                msg = msg.format(
                    self.cryptographic_length,
                    len(self.value) * 8
                )
                raise ValueError(msg)

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        key_wrapping_data = "key_wrapping_data={0}".format(
            self.key_wrapping_data
        )

        return "SymmetricKey({0}, {1}, {2}, {3})".format(
            algorithm,
            length,
            value,
            key_wrapping_data
        )

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
            elif self.key_wrapping_data != other.key_wrapping_data:
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
        key_wrapping_data(dict): A dictionary containing key wrapping data
            settings, describing how the key value has been wrapped.
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
                 name='Public Key', key_wrapping_data=None,
                 app_specific_info=None):
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
            key_wrapping_data(dict): A dictionary containing key wrapping data
                settings, describing how the key value has been wrapped.
                Optional, defaults to None.
            app_specific_info(list): A list of dictionaries containing
                application_namespace and application_data. Optional, defaults
                to None.
        """
        super(PublicKey, self).__init__(
            key_wrapping_data=key_wrapping_data
        )

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

        if app_specific_info:
            self._application_specific_informations = app_specific_info

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
        elif not isinstance(self.cryptographic_length, int):
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
            if not isinstance(name, str):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        format_type = "format_type={0}".format(self.key_format_type)
        key_wrapping_data = "key_wrapping_data={0}".format(
            self.key_wrapping_data
        )

        return "PublicKey({0}, {1}, {2}, {3}, {4})".format(
            algorithm, length, value, format_type, key_wrapping_data)

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
            elif self.key_wrapping_data != other.key_wrapping_data:
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
        key_wrapping_data(dict): A dictionary containing key wrapping data
            settings, describing how the key value has been wrapped.
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
                 name='Private Key', key_wrapping_data=None,
                 app_specific_info=None):
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
            key_wrapping_data(dict): A dictionary containing key wrapping data
                settings, describing how the key value has been wrapped.
                Optional, defaults to None.
            app_specific_info(list): A list of dictionaries containing
                application_namespace and application_data. Optional, defaults
                to None.
        """
        super(PrivateKey, self).__init__(
            key_wrapping_data=key_wrapping_data
        )

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

        if app_specific_info:
            self._application_specific_informations = app_specific_info

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
        elif not isinstance(self.cryptographic_length, int):
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
            if not isinstance(name, str):
                position = "({0} in list)".format(i)
                raise TypeError("key name {0} must be a string".format(
                    position))

    def __repr__(self):
        algorithm = "algorithm={0}".format(self.cryptographic_algorithm)
        length = "length={0}".format(self.cryptographic_length)
        value = "value={0}".format(binascii.hexlify(self.value))
        format_type = "format_type={0}".format(self.key_format_type)
        key_wrapping_data = "key_wrapping_data={0}".format(
            self.key_wrapping_data
        )

        return "PrivateKey({0}, {1}, {2}, {3}, {4})".format(
            algorithm, length, value, format_type, key_wrapping_data)

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
            elif self.key_wrapping_data != other.key_wrapping_data:
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

class SplitKey(Key):
    """
    """

    __mapper_args__ = {"polymorphic_identity": "SplitKey"}
    __table_args__ = {"sqlite_autoincrement": True}
    __tablename__ = "split_keys"

    unique_identifier = sqlalchemy.Column(
        "uid",
        sqlalchemy.Integer,
        sqlalchemy.ForeignKey("keys.uid"),
        primary_key=True
    )

    # Split Key object fields
    _split_key_parts = sqlalchemy.Column(
        "_split_key_parts",
        sqlalchemy.Integer,
        default=None
    )
    _key_part_identifier = sqlalchemy.Column(
        "_key_part_identifier",
        sqlalchemy.Integer,
        default=None
    )
    _split_key_threshold = sqlalchemy.Column(
        "_split_key_threshold",
        sqlalchemy.Integer,
        default=None
    )
    _split_key_method = sqlalchemy.Column(
        "_split_key_method",
        sql.EnumType(enums.SplitKeyMethod),
        default=None
    )
    _prime_field_size = sqlalchemy.Column(
        "_prime_field_size",
        sqlalchemy.BigInteger,
        default=None
    )

    def __init__(self,
                 cryptographic_algorithm=None,
                 cryptographic_length=None,
                 key_value=None,
                 cryptographic_usage_masks=None,
                 name="Split Key",
                 key_format_type=enums.KeyFormatType.RAW,
                 key_wrapping_data=None,
                 split_key_parts=None,
                 key_part_identifier=None,
                 split_key_threshold=None,
                 split_key_method=None,
                 prime_field_size=None):
        """
        Create a SplitKey.

        Args:
            cryptographic_algorithm(enum): A CryptographicAlgorithm enumeration
                identifying the type of algorithm for the split key. Required.
            cryptographic_length(int): The length in bits of the split key.
                Required.
            key_value(bytes): The bytes representing the split key. Required.
            cryptographic_usage_masks(list): A list of CryptographicUsageMask
                enumerations defining how the split key will be used. Optional,
                defaults to None.
            name(string): The string name of the split key. Optional, defaults
                to "Split Key".
            key_format_type (enum): A KeyFormatType enumeration specifying the
                format of the split key. Optional, defaults to Raw.
            key_wrapping_data(dict): A dictionary containing key wrapping data
                settings, describing how the split key has been wrapped.
                Optional, defaults to None.
            split_key_parts (int): An integer specifying the total number of
                parts of the split key. Required.
            key_part_identifier (int): An integer specifying which key part
                of the split key this key object represents. Required.
            split_key_threshold (int): An integer specifying the minimum
                number of key parts required to reconstruct the split key.
                Required.
            split_key_method (enum): A SplitKeyMethod enumeration specifying
                how the key was split. Required.
            prime_field_size (int): A big integer specifying the prime field
                size used for the Polynomial Sharing Prime Field split key
                method. Optional, defaults to None.
        """
        super(SplitKey, self).__init__(key_wrapping_data=key_wrapping_data)

        self._object_type = enums.ObjectType.SPLIT_KEY

        self.key_format_type = key_format_type
        self.value = key_value
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.names = [name]

        if cryptographic_usage_masks:
            self.cryptographic_usage_masks.extend(cryptographic_usage_masks)

        self.split_key_parts = split_key_parts
        self.key_part_identifier = key_part_identifier
        self.split_key_threshold = split_key_threshold
        self.split_key_method = split_key_method
        self.prime_field_size = prime_field_size

    @property
    def split_key_parts(self):
        return self._split_key_parts

    @split_key_parts.setter
    def split_key_parts(self, value):
        if (value is None) or (isinstance(value, int)):
            self._split_key_parts = value
        else:
            raise TypeError("The split key parts must be an integer.")

    @property
    def key_part_identifier(self):
        return self._key_part_identifier

    @key_part_identifier.setter
    def key_part_identifier(self, value):
        if (value is None) or (isinstance(value, int)):
            self._key_part_identifier = value
        else:
            raise TypeError("The key part identifier must be an integer.")

    @property
    def split_key_threshold(self):
        return self._split_key_threshold

    @split_key_threshold.setter
    def split_key_threshold(self, value):
        if (value is None) or (isinstance(value, int)):
            self._split_key_threshold = value
        else:
            raise TypeError("The split key threshold must be an integer.")

    @property
    def split_key_method(self):
        return self._split_key_method

    @split_key_method.setter
    def split_key_method(self, value):
        if (value is None) or (isinstance(value, enums.SplitKeyMethod)):
            self._split_key_method = value
        else:
            raise TypeError(
                "The split key method must be a SplitKeyMethod enumeration."
            )

    @property
    def prime_field_size(self):
        return self._prime_field_size

    @prime_field_size.setter
    def prime_field_size(self, value):
        if (value is None) or (isinstance(value, int)):
            self._prime_field_size = value
        else:
            raise TypeError("The prime field size must be an integer.")

    def __repr__(self):
        cryptographic_algorithm = "cryptographic_algorithm={0}".format(
            self.cryptographic_algorithm
        )
        cryptographic_length = "cryptographic_length={0}".format(
            self.cryptographic_length
        )
        key_value = "key_value={0}".format(binascii.hexlify(self.value))
        key_format_type = "key_format_type={0}".format(self.key_format_type)
        key_wrapping_data = "key_wrapping_data={0}".format(
            self.key_wrapping_data
        )
        cryptographic_usage_masks = "cryptographic_usage_masks={0}".format(
            self.cryptographic_usage_masks
        )
        names = "name={0}".format(self.names)
        split_key_parts = "split_key_parts={0}".format(self.split_key_parts)
        key_part_identifier = "key_part_identifier={0}".format(
            self.key_part_identifier
        )
        split_key_threshold = "split_key_threshold={0}".format(
            self.split_key_threshold
        )
        split_key_method = "split_key_method={0}".format(self.split_key_method)
        prime_field_size = "prime_field_size={0}".format(self.prime_field_size)

        return "SplitKey({0})".format(
            ", ".join(
                [
                    cryptographic_algorithm,
                    cryptographic_length,
                    key_value,
                    key_format_type,
                    key_wrapping_data,
                    cryptographic_usage_masks,
                    names,
                    split_key_parts,
                    key_part_identifier,
                    split_key_threshold,
                    split_key_method,
                    prime_field_size
                ]
            )
        )

    def __str__(self):
        return str(binascii.hexlify(self.value))

    def __eq__(self, other):
        if isinstance(other, SplitKey):
            if self.value != other.value:
                return False
            elif self.key_format_type != other.key_format_type:
                return False
            elif self.cryptographic_algorithm != other.cryptographic_algorithm:
                return False
            elif self.cryptographic_length != other.cryptographic_length:
                return False
            elif self.key_wrapping_data != other.key_wrapping_data:
                return False
            elif self.cryptographic_usage_masks != \
                    other.cryptographic_usage_masks:
                return False
            elif self.names != other.names:
                return False
            elif self.split_key_parts != other.split_key_parts:
                return False
            elif self.key_part_identifier != other.key_part_identifier:
                return False
            elif self.split_key_threshold != other.split_key_threshold:
                return False
            elif self.split_key_method != other.split_key_method:
                return False
            elif self.prime_field_size != other.prime_field_size:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, SplitKey):
            return not (self == other)
        else:
            return NotImplemented

event.listen(
    SplitKey._names,
    "append",
    sql.attribute_append_factory("name_index"),
    retval=False
)

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
        'certificate_type', sql.EnumType(enums.CertificateType))

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
                            enums.CertificateType):
            raise TypeError("certificate type must be a CertificateType "
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
            if not isinstance(name, str):
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
        'polymorphic_identity': 'X509Certificate'
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
            enums.CertificateType.X_509, value, masks, name)

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

    def __init__(self, value, data_type, masks=None, name='Secret Data',
                 app_specific_info=None):
        """
        Create a SecretData object.

        Args:
            value(bytes): The bytes representing secret data.
            data_type(SecretDataType): An enumeration defining the type of the
                secret value.
            masks(list): A list of CryptographicUsageMask enumerations
                defining how the key will be used.
            name(string): The string name of the key.
            app_specific_info(list): A list of dictionaries containing
                application_namespace and application_data. Optional, defaults
                to None.
        """
        super(SecretData, self).__init__()

        self._object_type = enums.ObjectType.SECRET_DATA

        self.value = value
        self.data_type = data_type
        self.names = [name]

        if app_specific_info:
            self._application_specific_informations = app_specific_info

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
            if not isinstance(name, str):
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
            if not isinstance(name, str):
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

class ApplicationSpecificInformation(sql.Base):
    __tablename__ = "app_specific_info"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    _application_namespace = sqlalchemy.Column(
        "application_namespace",
        sqlalchemy.String
    )
    _application_data = sqlalchemy.Column(
        "application_data",
        sqlalchemy.String
    )
    managed_objects = sqlalchemy.orm.relationship(
        "ManagedObject",
        secondary=app_specific_info_map,
        back_populates="app_specific_info"
    )

    def __init__(self,
                 application_namespace=None,
                 application_data=None):
        """
        Create an ApplicationSpecificInformation attribute.

        Args:
            application_namespace (str): A string specifying the application
                namespace. Required.
            application_data (str): A string specifying the application data.
                Required.
        """
        super(ApplicationSpecificInformation, self).__init__()

        self.application_namespace = application_namespace
        self.application_data = application_data

    @property
    def application_namespace(self):
        return self._application_namespace

    @application_namespace.setter
    def application_namespace(self, value):
        if (value is None) or (isinstance(value, str)):
            self._application_namespace = value
        else:
            raise TypeError("The application namespace must be a string.")

    @property
    def application_data(self):
        return self._application_data

    @application_data.setter
    def application_data(self, value):
        if (value is None) or (isinstance(value, str)):
            self._application_data = value
        else:
            raise TypeError("The application data must be a string.")

    def __repr__(self):
        application_namespace = "application_namespace='{}'".format(
            self.application_namespace
        )
        application_data = "application_data='{}'".format(
            self.application_data
        )

        return "ApplicationSpecificInformation({})".format(
            ", ".join(
                [
                    application_namespace,
                    application_data
                ]
            )
        )

    def __str__(self):
        return str(
            {
                "application_namespace": self.application_namespace,
                "application_data": self.application_data
            }
        )

    def __eq__(self, other):
        if isinstance(other, ApplicationSpecificInformation):
            if self.application_namespace != other.application_namespace:
                return False
            elif self.application_data != other.application_data:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ApplicationSpecificInformation):
            return not (self == other)
        else:
            return NotImplemented

class ObjectGroup(sql.Base):
    __tablename__ = "object_groups"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    _object_group = sqlalchemy.Column(
        "object_group",
        sqlalchemy.String,
        nullable=False
    )
    managed_objects = sqlalchemy.orm.relationship(
        "ManagedObject",
        secondary=object_group_map,
        back_populates="object_groups"
    )

    def __init__(self, object_group=None):
        """
        Create an ObjectGroup attribute.

        Args:
            object_group (str): A string specifying the object group. Required.
        """
        super(ObjectGroup, self).__init__()

        self.object_group = object_group

    @property
    def object_group(self):
        return self._object_group

    @object_group.setter
    def object_group(self, value):
        if (value is None) or (isinstance(value, str)):
            self._object_group = value
        else:
            raise TypeError("The object group must be a string.")

    def __repr__(self):
        object_group = "object_group='{}'".format(self.object_group)

        return "ObjectGroup({})".format(object_group)

    def __str__(self):
        return str({"object_group": self.object_group})

    def __eq__(self, other):
        if isinstance(other, ObjectGroup):
            if self.object_group != other.object_group:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ObjectGroup):
            return not (self == other)
        else:
            return NotImplemented
