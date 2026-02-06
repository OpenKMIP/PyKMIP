# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

import sqlalchemy
import testtools
import time

from unittest import mock

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects as core_objects
from kmip.core import secrets
from kmip.core.factories import attributes as attribute_factory
from kmip.core.messages import contents
from kmip.core.messages import payloads

from kmip.pie import objects as pie_objects
from kmip.pie import sqltypes

from kmip.services.server import engine as kmip_engine


def _mask_value(masks):
    mask = 0
    for flag in masks:
        mask |= flag.value
    return mask


def _build_attribute_dict(algorithm=None, length=None, usage_masks=None):
    attributes_dict = {}
    if algorithm is not None:
        attributes_dict['Cryptographic Algorithm'] = \
            attributes.CryptographicAlgorithm(algorithm)
    if length is not None:
        attributes_dict['Cryptographic Length'] = \
            attributes.CryptographicLength(length)
    if usage_masks is not None:
        attributes_dict['Cryptographic Usage Mask'] = \
            attributes.CryptographicUsageMask(_mask_value(usage_masks))
    return attributes_dict


class DummyManagedObject(object):
    def __init__(self, unique_identifier, object_type, attributes_map=None):
        self.unique_identifier = unique_identifier
        self.object_type = object_type
        self._object_type = object_type
        self.initial_date = 0
        self._attributes = attributes_map or {}


class TestKmipEngineProcessExtended(testtools.TestCase):

    def setUp(self):
        super(TestKmipEngineProcessExtended, self).setUp()
        self.engine_instance = sqlalchemy.create_engine('sqlite://', echo=False)
        sqltypes.Base.metadata.create_all(self.engine_instance)
        self.session_factory = sqlalchemy.orm.sessionmaker(
            bind=self.engine_instance,
            expire_on_commit=False
        )

        self.engine = kmip_engine.KmipEngine()
        self.engine._data_store = self.engine_instance
        self.engine._data_store_session_factory = self.session_factory
        self.engine._data_session = self.engine._data_store_session_factory()
        self.engine._logger = mock.MagicMock()
        self.engine._is_allowed_by_operation_policy = \
            mock.Mock(return_value=True)
        self.engine._cryptography_engine = mock.MagicMock()

    def tearDown(self):
        self.engine._data_session.close()
        super(TestKmipEngineProcessExtended, self).tearDown()

    def _make_symmetric_key(self, state=enums.State.ACTIVE, masks=None):
        if masks is None:
            masks = [enums.CryptographicUsageMask.ENCRYPT,
                     enums.CryptographicUsageMask.DECRYPT]
        key = pie_objects.SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            b'\x01' * 16,
            masks=masks
        )
        key.state = state
        return key

    def _make_public_key(self, state=enums.State.ACTIVE, masks=None):
        if masks is None:
            masks = [enums.CryptographicUsageMask.VERIFY]
        key = pie_objects.PublicKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            b'pub',
            format_type=enums.KeyFormatType.PKCS_1,
            masks=masks
        )
        key.state = state
        return key

    def _make_private_key(self, state=enums.State.ACTIVE, masks=None):
        if masks is None:
            masks = [enums.CryptographicUsageMask.SIGN]
        key = pie_objects.PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            b'priv',
            format_type=enums.KeyFormatType.PKCS_8,
            masks=masks
        )
        key.state = state
        return key

    def _add_managed_object(self, managed_object):
        self.engine._data_session.add(managed_object)
        self.engine._data_session.commit()
        return str(managed_object.unique_identifier)

    def _build_new_attribute(self, attribute_type, value):
        factory = attribute_factory.AttributeFactory()
        attribute = factory.create_attribute(attribute_type, value)
        return core_objects.NewAttribute(attribute)

    def test_process_create_multiple_algorithms(self):
        """Test Create succeeds for multiple symmetric key algorithms."""
        e = self.engine
        e._process_template_attribute = mock.Mock()

        def _create_key(algorithm, length):
            return {'value': b'\x00' * (length // 8)}

        e._cryptography_engine.create_symmetric_key.side_effect = _create_key

        cases = [
            (enums.CryptographicAlgorithm.AES, 128),
            (enums.CryptographicAlgorithm.TRIPLE_DES, 192),
            (enums.CryptographicAlgorithm.BLOWFISH, 128),
            (enums.CryptographicAlgorithm.CAMELLIA, 128)
        ]

        for algorithm, length in cases:
            with self.subTest(algorithm=algorithm, length=length):
                e._process_template_attribute.return_value = \
                    _build_attribute_dict(
                        algorithm=algorithm,
                        length=length,
                        usage_masks=[enums.CryptographicUsageMask.ENCRYPT]
                    )
                payload = payloads.CreateRequestPayload(
                    enums.ObjectType.SYMMETRIC_KEY,
                    template_attribute=core_objects.TemplateAttribute()
                )
                response = e._process_create(payload)
                self.assertEqual(enums.ObjectType.SYMMETRIC_KEY,
                                 response.object_type)
                e._cryptography_engine.create_symmetric_key.assert_called_with(
                    algorithm,
                    length
                )
                e._cryptography_engine.create_symmetric_key.reset_mock()

    def test_process_create_missing_attributes(self):
        """Test Create raises for missing required attributes."""
        e = self.engine
        e._process_template_attribute = mock.Mock()

        cases = [
            ({'Cryptographic Length': attributes.CryptographicLength(128)},
             "The cryptographic algorithm must be specified as an attribute."),
            ({
                'Cryptographic Algorithm':
                    attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.AES
                    ),
                'Cryptographic Usage Mask':
                    attributes.CryptographicUsageMask(
                        _mask_value([enums.CryptographicUsageMask.ENCRYPT])
                    )
            }, "The cryptographic length must be specified as an attribute."),
            ({
                'Cryptographic Algorithm':
                    attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.AES
                    ),
                'Cryptographic Length':
                    attributes.CryptographicLength(128)
            }, "The cryptographic usage mask must be specified as an attribute.")
        ]

        for attrs, message in cases:
            with self.subTest(message=message):
                e._process_template_attribute.return_value = attrs
                payload = payloads.CreateRequestPayload(
                    enums.ObjectType.SYMMETRIC_KEY,
                    template_attribute=core_objects.TemplateAttribute()
                )
                self.assertRaisesRegex(
                    exceptions.InvalidField,
                    message,
                    e._process_create,
                    payload
                )

    def test_process_create_invalid_length(self):
        """Test Create propagates invalid cryptographic length errors."""
        e = self.engine
        e._process_template_attribute = mock.Mock(return_value=
            _build_attribute_dict(
                algorithm=enums.CryptographicAlgorithm.AES,
                length=999,
                usage_masks=[enums.CryptographicUsageMask.ENCRYPT]
            )
        )

        e._cryptography_engine.create_symmetric_key.side_effect = \
            exceptions.InvalidField("invalid length")

        payload = payloads.CreateRequestPayload(
            enums.ObjectType.SYMMETRIC_KEY,
            template_attribute=core_objects.TemplateAttribute()
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "invalid length",
            e._process_create,
            payload
        )

    def test_process_create_key_pair_rsa_multiple_lengths(self):
        """Test CreateKeyPair succeeds for RSA with multiple lengths."""
        e = self.engine
        e._process_template_attribute = mock.Mock()

        def _create_pair(algorithm, length):
            return ({'value': b'pub', 'format': enums.KeyFormatType.PKCS_1},
                    {'value': b'priv', 'format': enums.KeyFormatType.PKCS_8})

        e._cryptography_engine.create_asymmetric_key_pair.side_effect = \
            _create_pair

        lengths = [1024, 2048]
        for length in lengths:
            with self.subTest(length=length):
                public_attrs = _build_attribute_dict(
                    usage_masks=[enums.CryptographicUsageMask.ENCRYPT]
                )
                private_attrs = _build_attribute_dict(
                    usage_masks=[enums.CryptographicUsageMask.DECRYPT]
                )
                common_attrs = _build_attribute_dict(
                    algorithm=enums.CryptographicAlgorithm.RSA,
                    length=length
                )
                e._process_template_attribute.side_effect = [
                    public_attrs,
                    private_attrs,
                    common_attrs
                ]
                payload = payloads.CreateKeyPairRequestPayload(
                    common_template_attribute=core_objects.CommonTemplateAttribute(),
                    private_key_template_attribute=core_objects.PrivateKeyTemplateAttribute(),
                    public_key_template_attribute=core_objects.PublicKeyTemplateAttribute()
                )
                response = e._process_create_key_pair(payload)
                self.assertIsNotNone(response.public_key_unique_identifier)
                self.assertIsNotNone(response.private_key_unique_identifier)
                e._cryptography_engine.create_asymmetric_key_pair.\
                    assert_called_with(enums.CryptographicAlgorithm.RSA, length)
                e._cryptography_engine.create_asymmetric_key_pair.reset_mock()

    def test_process_create_key_pair_missing_usage_mask(self):
        """Test CreateKeyPair raises when usage masks are missing."""
        e = self.engine
        e._process_template_attribute = mock.Mock()
        e._process_template_attribute.side_effect = [
            _build_attribute_dict(
                algorithm=enums.CryptographicAlgorithm.RSA,
                length=1024
            ),
            _build_attribute_dict(
                algorithm=enums.CryptographicAlgorithm.RSA,
                length=1024
            ),
            _build_attribute_dict(
                algorithm=enums.CryptographicAlgorithm.RSA,
                length=1024
            )
        ]

        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=core_objects.CommonTemplateAttribute(),
            private_key_template_attribute=core_objects.PrivateKeyTemplateAttribute(),
            public_key_template_attribute=core_objects.PublicKeyTemplateAttribute()
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "cryptographic usage mask must be specified",
            e._process_create_key_pair,
            payload
        )

    def test_process_create_key_pair_mismatched_lengths(self):
        """Test CreateKeyPair raises for mismatched key lengths."""
        e = self.engine
        e._process_template_attribute = mock.Mock()

        public_attrs = _build_attribute_dict(
            algorithm=enums.CryptographicAlgorithm.RSA,
            length=1024,
            usage_masks=[enums.CryptographicUsageMask.ENCRYPT]
        )
        private_attrs = _build_attribute_dict(
            algorithm=enums.CryptographicAlgorithm.RSA,
            length=2048,
            usage_masks=[enums.CryptographicUsageMask.DECRYPT]
        )
        common_attrs = {}

        e._process_template_attribute.side_effect = [
            public_attrs,
            private_attrs,
            common_attrs
        ]

        payload = payloads.CreateKeyPairRequestPayload(
            common_template_attribute=core_objects.CommonTemplateAttribute(),
            private_key_template_attribute=core_objects.PrivateKeyTemplateAttribute(),
            public_key_template_attribute=core_objects.PublicKeyTemplateAttribute()
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "public and private key lengths must be the same",
            e._process_create_key_pair,
            payload
        )

    def test_process_register_supported_object_types(self):
        """Test Register succeeds for all supported object types."""
        e = self.engine

        secret_map = {
            enums.ObjectType.SYMMETRIC_KEY: secrets.SymmetricKey(),
            enums.ObjectType.PUBLIC_KEY: secrets.PublicKey(),
            enums.ObjectType.PRIVATE_KEY: secrets.PrivateKey(),
            enums.ObjectType.CERTIFICATE: secrets.Certificate(),
            enums.ObjectType.SECRET_DATA: secrets.SecretData(),
            enums.ObjectType.OPAQUE_DATA: secrets.OpaqueObject(),
            enums.ObjectType.SPLIT_KEY: secrets.SplitKey()
        }

        pie_map = {
            enums.ObjectType.SYMMETRIC_KEY: pie_objects.SymmetricKey(
                enums.CryptographicAlgorithm.AES,
                128,
                b'\x00' * 16
            ),
            enums.ObjectType.PUBLIC_KEY: pie_objects.PublicKey(
                enums.CryptographicAlgorithm.RSA,
                1024,
                b'pub',
                format_type=enums.KeyFormatType.PKCS_1
            ),
            enums.ObjectType.PRIVATE_KEY: pie_objects.PrivateKey(
                enums.CryptographicAlgorithm.RSA,
                1024,
                b'priv',
                format_type=enums.KeyFormatType.PKCS_8
            ),
            enums.ObjectType.CERTIFICATE: pie_objects.X509Certificate(
                b'cert'
            ),
            enums.ObjectType.SECRET_DATA: pie_objects.SecretData(
                b'secret',
                enums.SecretDataType.PASSWORD
            ),
            enums.ObjectType.OPAQUE_DATA: pie_objects.OpaqueObject(
                b'opaque',
                enums.OpaqueDataType.NONE
            ),
            enums.ObjectType.SPLIT_KEY: pie_objects.SplitKey(
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                cryptographic_length=128,
                key_value=b'\x00' * 16,
                split_key_parts=2,
                key_part_identifier=1,
                split_key_threshold=2,
                split_key_method=enums.SplitKeyMethod.XOR,
                prime_field_size=257
            )
        }

        def _convert(secret):
            for obj_type, obj in secret_map.items():
                if isinstance(secret, type(obj)):
                    return pie_map[obj_type]
            raise TypeError("unsupported")

        with mock.patch(
            'kmip.services.server.engine.factory.ObjectFactory'
        ) as factory_mock:
            factory_instance = factory_mock.return_value
            factory_instance.convert.side_effect = _convert

            for obj_type, secret in secret_map.items():
                with self.subTest(object_type=obj_type):
                    payload = payloads.RegisterRequestPayload(
                        object_type=obj_type,
                        managed_object=secret
                    )
                    response = e._process_register(payload)
                    self.assertIsNotNone(response.unique_identifier)

    def test_process_register_unsupported_object_type(self):
        """Test Register rejects unsupported object types."""
        e = self.engine
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.TEMPLATE,
            managed_object=secrets.Template()
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "object type is not supported",
            e._process_register,
            payload
        )

    def test_process_register_missing_managed_object(self):
        """Test Register rejects missing managed objects."""
        e = self.engine
        payload = payloads.RegisterRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            managed_object=None
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Cannot register a secret in absentia",
            e._process_register,
            payload
        )

    def test_process_get_without_wrapping(self):
        """Test Get returns a core secret without wrapping."""
        e = self.engine
        managed_object = self._make_symmetric_key()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )

        payload = payloads.GetRequestPayload(
            unique_identifier='1'
        )
        response = e._process_get(payload)
        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, response.object_type)
        self.assertEqual('1', response.unique_identifier)

    def test_process_get_with_wrapping(self):
        """Test Get wraps keys when a wrapping specification is provided."""
        e = self.engine
        target_object = self._make_symmetric_key()
        wrapping_key = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.WRAP_KEY]
        )

        e._get_object_with_access_controls = mock.Mock(
            side_effect=[target_object, wrapping_key]
        )
        e._cryptography_engine.wrap_key.return_value = b'wrapped'

        key_info = core_objects.EncryptionKeyInformation(
            unique_identifier='wrap-id',
            cryptographic_parameters=attributes.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.NIST_KEY_WRAP
            )
        )
        spec = core_objects.KeyWrappingSpecification(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=key_info,
            encoding_option=enums.EncodingOption.NO_ENCODING
        )
        payload = payloads.GetRequestPayload(
            unique_identifier='1',
            key_wrapping_specification=spec
        )

        response = e._process_get(payload)
        self.assertEqual('1', response.unique_identifier)
        e._cryptography_engine.wrap_key.assert_called_once()

    def test_process_get_key_format_mismatch(self):
        """Test Get rejects unsupported key format conversions."""
        e = self.engine
        managed_object = self._make_symmetric_key()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )

        payload = payloads.GetRequestPayload(
            unique_identifier='1',
            key_format_type=enums.KeyFormatType.PKCS_1
        )
        self.assertRaisesRegex(
            exceptions.KeyFormatTypeNotSupported,
            "Key format conversion",
            e._process_get,
            payload
        )

    def test_process_destroy_states(self):
        """Test Destroy succeeds for pre-active and deactivated objects."""
        e = self.engine

        for state in [enums.State.PRE_ACTIVE, enums.State.DEACTIVATED]:
            with self.subTest(state=state):
                obj = self._make_symmetric_key(state=state)
                uid = self._add_managed_object(obj)
                payload = payloads.DestroyRequestPayload(
                    unique_identifier=attributes.UniqueIdentifier(uid)
                )
                response = e._process_destroy(payload)
                self.assertEqual(uid, response.unique_identifier.value)

    def test_process_destroy_active_denied(self):
        """Test Destroy rejects active objects."""
        e = self.engine
        obj = self._make_symmetric_key(state=enums.State.ACTIVE)
        uid = self._add_managed_object(obj)
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Object is active",
            e._process_destroy,
            payload
        )

    def test_process_destroy_compromised(self):
        """Test Destroy succeeds for compromised objects."""
        e = self.engine
        obj = self._make_symmetric_key(state=enums.State.COMPROMISED)
        uid = self._add_managed_object(obj)
        payload = payloads.DestroyRequestPayload(
            unique_identifier=attributes.UniqueIdentifier(uid)
        )
        response = e._process_destroy(payload)
        self.assertEqual(uid, response.unique_identifier.value)

    def test_process_locate_filters(self):
        """Test Locate filters by name, algorithm, and state."""
        e = self.engine
        e._attribute_policy.is_attribute_applicable_to_object_type = \
            mock.Mock(return_value=True)

        obj_match = DummyManagedObject(
            unique_identifier='1',
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes_map={
                'Name': [attributes.Name.create(
                    'Key-1',
                    enums.NameType.UNINTERPRETED_TEXT_STRING
                )],
                'Cryptographic Algorithm': enums.CryptographicAlgorithm.AES,
                'State': enums.State.ACTIVE
            }
        )
        obj_miss = DummyManagedObject(
            unique_identifier='2',
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            attributes_map={
                'Name': [attributes.Name.create(
                    'Other',
                    enums.NameType.UNINTERPRETED_TEXT_STRING
                )],
                'Cryptographic Algorithm': enums.CryptographicAlgorithm.AES,
                'State': enums.State.DESTROYED
            }
        )

        def _get_attr(obj, name):
            return obj._attributes.get(name)

        e._get_attribute_from_managed_object = mock.Mock(side_effect=_get_attr)
        e._list_objects_with_access_controls = mock.Mock(
            return_value=[obj_match, obj_miss]
        )

        factory = attribute_factory.AttributeFactory()
        attrs = [
            factory.create_attribute(
                enums.AttributeType.NAME,
                attributes.Name.create(
                    'Key-1',
                    enums.NameType.UNINTERPRETED_TEXT_STRING
                )
            ),
            factory.create_attribute(
                enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                enums.CryptographicAlgorithm.AES
            ),
            factory.create_attribute(
                enums.AttributeType.STATE,
                enums.State.ACTIVE
            )
        ]
        payload = payloads.LocateRequestPayload(attributes=attrs)
        response = e._process_locate(payload)
        self.assertEqual(['1'], response.unique_identifiers)

    def test_process_locate_offset_and_max_items(self):
        """Test Locate applies offset and maximum items after sorting."""
        e = self.engine
        e._attribute_policy.is_attribute_applicable_to_object_type = \
            mock.Mock(return_value=True)

        obj_a = DummyManagedObject('1', enums.ObjectType.SYMMETRIC_KEY)
        obj_b = DummyManagedObject('2', enums.ObjectType.SYMMETRIC_KEY)
        obj_c = DummyManagedObject('3', enums.ObjectType.SYMMETRIC_KEY)
        obj_a.initial_date = 1
        obj_b.initial_date = 2
        obj_c.initial_date = 3

        e._get_attribute_from_managed_object = mock.Mock(return_value=None)
        e._list_objects_with_access_controls = mock.Mock(
            return_value=[obj_a, obj_b, obj_c]
        )

        payload = payloads.LocateRequestPayload(
            maximum_items=1,
            offset_items=1
        )
        response = e._process_locate(payload)
        self.assertEqual(['2'], response.unique_identifiers)

    def test_process_locate_invalid_date_filters(self):
        """Test Locate rejects too many date attributes."""
        e = self.engine
        e._attribute_policy.is_attribute_applicable_to_object_type = \
            mock.Mock(return_value=True)

        obj = DummyManagedObject('1', enums.ObjectType.SYMMETRIC_KEY)
        obj.initial_date = 10
        e._get_attribute_from_managed_object = \
            mock.Mock(return_value=obj.initial_date)
        e._list_objects_with_access_controls = mock.Mock(return_value=[obj])

        factory = attribute_factory.AttributeFactory()
        attrs = [
            factory.create_attribute(
                enums.AttributeType.INITIAL_DATE,
                1
            ),
            factory.create_attribute(
                enums.AttributeType.INITIAL_DATE,
                2
            ),
            factory.create_attribute(
                enums.AttributeType.INITIAL_DATE,
                3
            )
        ]

        payload = payloads.LocateRequestPayload(attributes=attrs)
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "Too many Initial Date attributes",
            e._process_locate,
            payload
        )

    def test_process_activate_success(self):
        """Test Activate succeeds for pre-active objects."""
        e = self.engine
        managed_object = mock.Mock()
        managed_object._object_type = enums.ObjectType.SYMMETRIC_KEY
        managed_object.state = enums.State.PRE_ACTIVE
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        payload = payloads.ActivateRequestPayload(
            attributes.UniqueIdentifier('1')
        )
        response = e._process_activate(payload)
        self.assertEqual(enums.State.ACTIVE, managed_object.state)
        self.assertEqual('1', response.unique_identifier.value)

    def test_process_activate_invalid_state(self):
        """Test Activate rejects non-pre-active objects."""
        e = self.engine
        managed_object = mock.Mock()
        managed_object._object_type = enums.ObjectType.SYMMETRIC_KEY
        managed_object.state = enums.State.ACTIVE
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        payload = payloads.ActivateRequestPayload(
            attributes.UniqueIdentifier('1')
        )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "not pre-active",
            e._process_activate,
            payload
        )

    def test_process_activate_no_state(self):
        """Test Activate rejects objects without state."""
        e = self.engine
        managed_object = mock.Mock()
        managed_object._object_type = enums.ObjectType.OPAQUE_DATA
        managed_object.state = None
        del managed_object.state
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        payload = payloads.ActivateRequestPayload(
            attributes.UniqueIdentifier('1')
        )
        self.assertRaisesRegex(
            exceptions.IllegalOperation,
            "has no state",
            e._process_activate,
            payload
        )

    def test_process_revoke_key_compromise(self):
        """Test Revoke with KEY_COMPROMISE transitions state."""
        e = self.engine
        managed_object = mock.Mock()
        managed_object._object_type = enums.ObjectType.SYMMETRIC_KEY
        managed_object.state = enums.State.ACTIVE
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )

        reason = core_objects.RevocationReason(
            code=enums.RevocationReasonCode.KEY_COMPROMISE
        )
        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier('1'),
            revocation_reason=reason
        )
        response = e._process_revoke(payload)
        self.assertEqual(enums.State.COMPROMISED, managed_object.state)
        self.assertEqual('1', response.unique_identifier.value)

    def test_process_revoke_missing_reason(self):
        """Test Revoke rejects requests without revocation reason."""
        e = self.engine
        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier('1')
        )
        payload.revocation_reason = None
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "revocation reason code must be specified",
            e._process_revoke,
            payload
        )

    def test_process_revoke_non_active(self):
        """Test Revoke rejects non-active objects for non-compromise reasons."""
        e = self.engine
        managed_object = mock.Mock()
        managed_object._object_type = enums.ObjectType.SYMMETRIC_KEY
        managed_object.state = enums.State.PRE_ACTIVE
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        reason = core_objects.RevocationReason(
            code=enums.RevocationReasonCode.CESSATION_OF_OPERATION
        )
        payload = payloads.RevokeRequestPayload(
            unique_identifier=attributes.UniqueIdentifier('1'),
            revocation_reason=reason
        )
        self.assertRaisesRegex(
            exceptions.IllegalOperation,
            "not active",
            e._process_revoke,
            payload
        )

    def test_process_delete_attribute_v2_current_attribute(self):
        """Test DeleteAttribute (KMIP 2.0) deletes by current attribute."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._delete_attribute_from_managed_object = mock.Mock()

        name_attr = attributes.Name(
            attributes.Name.NameValue('delete-me'),
            attributes.Name.NameType(enums.NameType.UNINTERPRETED_TEXT_STRING)
        )
        current_attr = core_objects.CurrentAttribute(attribute=name_attr)
        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier='1',
            current_attribute=current_attr
        )

        response = e._process_delete_attribute(payload)
        self.assertEqual('1', response.unique_identifier)
        e._delete_attribute_from_managed_object.assert_called_once()
        args, _ = e._delete_attribute_from_managed_object.call_args
        self.assertEqual(managed_object, args[0])
        self.assertEqual('Name', args[1][0])
        self.assertIsNone(args[1][1])
        self.assertEqual(name_attr, args[1][2])

    def test_process_delete_attribute_v2_missing_reference(self):
        """Test DeleteAttribute (KMIP 2.0) rejects missing attribute data."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        e._get_object_with_access_controls = mock.Mock()

        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier='1'
        )
        self.assertRaisesRegex(
            exceptions.InvalidMessage,
            "must specify the current",
            e._process_delete_attribute,
            payload
        )

    def test_process_delete_attribute_v1_index_out_of_range(self):
        """Test DeleteAttribute (KMIP 1.x) rejects out-of-range index."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(1, 2)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._get_attributes_from_managed_object = mock.Mock(
            return_value=[mock.Mock()]
        )

        payload = payloads.DeleteAttributeRequestPayload(
            unique_identifier='1',
            attribute_name='Name',
            attribute_index=1
        )
        self.assertRaisesRegex(
            exceptions.ItemNotFound,
            "specified index",
            e._process_delete_attribute,
            payload
        )

    def test_process_set_attribute_success(self):
        """Test SetAttribute (KMIP 2.0) sets a single-valued attribute."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._attribute_policy.is_attribute_multivalued = mock.Mock(
            return_value=False
        )
        e._attribute_policy.is_attribute_modifiable_by_client = mock.Mock(
            return_value=True
        )
        e._set_attributes_on_managed_object = mock.Mock()

        new_attr = self._build_new_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'new-name',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        payload = payloads.SetAttributeRequestPayload(
            unique_identifier='1',
            new_attribute=new_attr
        )

        response = e._process_set_attribute(payload)
        self.assertEqual('1', response.unique_identifier)
        e._set_attributes_on_managed_object.assert_called_once()

    def test_process_set_attribute_multivalued_rejected(self):
        """Test SetAttribute rejects multi-valued attributes."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._attribute_policy.is_attribute_multivalued = mock.Mock(
            return_value=True
        )
        e._attribute_policy.is_attribute_modifiable_by_client = mock.Mock(
            return_value=True
        )

        new_attr = self._build_new_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'multi',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        payload = payloads.SetAttributeRequestPayload(
            unique_identifier='1',
            new_attribute=new_attr
        )

        self.assertRaisesRegex(
            exceptions.KmipError,
            "multi-valued",
            e._process_set_attribute,
            payload
        )

    def test_process_set_attribute_read_only_rejected(self):
        """Test SetAttribute rejects read-only attributes."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._attribute_policy.is_attribute_multivalued = mock.Mock(
            return_value=False
        )
        e._attribute_policy.is_attribute_modifiable_by_client = mock.Mock(
            return_value=False
        )

        new_attr = self._build_new_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'readonly',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        payload = payloads.SetAttributeRequestPayload(
            unique_identifier='1',
            new_attribute=new_attr
        )

        self.assertRaisesRegex(
            exceptions.KmipError,
            "read-only",
            e._process_set_attribute,
            payload
        )

    def test_process_modify_attribute_v2_single_value_success(self):
        """Test ModifyAttribute (KMIP 2.0) updates a single-valued attribute."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._attribute_policy.is_attribute_modifiable_by_client = mock.Mock(
            return_value=True
        )
        e._attribute_policy.is_attribute_multivalued = mock.Mock(
            return_value=False
        )
        e._get_attribute_from_managed_object = mock.Mock(
            return_value='existing'
        )
        e._set_attribute_on_managed_object = mock.Mock()

        new_attr = self._build_new_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'updated',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier='1',
            new_attribute=new_attr
        )

        response = e._process_modify_attribute(payload)
        self.assertEqual('1', response.unique_identifier)
        e._set_attribute_on_managed_object.assert_called_once()

    def test_process_modify_attribute_v2_multivalue_missing_current(self):
        """Test ModifyAttribute (KMIP 2.0) requires current attribute."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._attribute_policy.is_attribute_modifiable_by_client = mock.Mock(
            return_value=True
        )
        e._attribute_policy.is_attribute_multivalued = mock.Mock(
            return_value=True
        )

        new_attr = self._build_new_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'new',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier='1',
            new_attribute=new_attr
        )

        self.assertRaisesRegex(
            exceptions.KmipError,
            "current attribute must be specified",
            e._process_modify_attribute,
            payload
        )

    def test_process_modify_attribute_v2_read_only(self):
        """Test ModifyAttribute (KMIP 2.0) rejects read-only attributes."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(2, 0)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._attribute_policy.is_attribute_modifiable_by_client = mock.Mock(
            return_value=False
        )
        e._attribute_policy.is_attribute_multivalued = mock.Mock(
            return_value=False
        )

        new_attr = self._build_new_attribute(
            enums.AttributeType.NAME,
            attributes.Name.create(
                'readonly',
                enums.NameType.UNINTERPRETED_TEXT_STRING
            )
        )
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier='1',
            new_attribute=new_attr
        )

        self.assertRaisesRegex(
            exceptions.KmipError,
            "read-only",
            e._process_modify_attribute,
            payload
        )

    def test_process_modify_attribute_v1_invalid_index(self):
        """Test ModifyAttribute (KMIP 1.x) rejects index on single value."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(1, 2)
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._attribute_policy.is_attribute_modifiable_by_client = mock.Mock(
            return_value=True
        )
        e._attribute_policy.is_attribute_multivalued = mock.Mock(
            return_value=False
        )
        e._get_attributes_from_managed_object = mock.Mock(
            return_value=[mock.Mock()]
        )

        attribute = core_objects.Attribute(
            attribute_name=core_objects.Attribute.AttributeName('State'),
            attribute_index=core_objects.Attribute.AttributeIndex(1),
            attribute_value=attributes.State(enums.State.ACTIVE)
        )
        payload = payloads.ModifyAttributeRequestPayload(
            unique_identifier='1',
            attribute=attribute
        )

        self.assertRaisesRegex(
            exceptions.KmipError,
            "attribute index cannot be specified",
            e._process_modify_attribute,
            payload
        )

    def test_process_get_attributes_success(self):
        """Test GetAttributes returns attributes for a managed object."""
        e = self.engine
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        attr_factory = attribute_factory.AttributeFactory()
        attr = attr_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.AES
        )
        e._get_attributes_from_managed_object = mock.Mock(
            return_value=[attr]
        )
        payload = payloads.GetAttributesRequestPayload(
            unique_identifier='1',
            attribute_names=['Cryptographic Algorithm']
        )

        response = e._process_get_attributes(payload)
        self.assertEqual('1', response.unique_identifier)
        self.assertEqual([attr], response.attributes)

    def test_process_get_attributes_permission_denied(self):
        """Test GetAttributes propagates permission errors."""
        e = self.engine
        e._get_object_with_access_controls = mock.Mock(
            side_effect=exceptions.PermissionDenied("denied")
        )
        payload = payloads.GetAttributesRequestPayload(
            unique_identifier='1'
        )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "denied",
            e._process_get_attributes,
            payload
        )

    def test_process_get_attributes_id_placeholder(self):
        """Test GetAttributes uses the ID placeholder when missing."""
        e = self.engine
        e._id_placeholder = 'placeholder'
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._get_attributes_from_managed_object = mock.Mock(return_value=[])
        payload = payloads.GetAttributesRequestPayload()

        response = e._process_get_attributes(payload)
        self.assertEqual('placeholder', response.unique_identifier)
        e._get_object_with_access_controls.assert_called_with(
            'placeholder',
            enums.Operation.GET_ATTRIBUTES
        )

    def test_process_get_attribute_list_success(self):
        """Test GetAttributeList returns attribute names."""
        e = self.engine
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        attr_factory = attribute_factory.AttributeFactory()
        attrs_list = [
            attr_factory.create_attribute(
                enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
                enums.CryptographicAlgorithm.AES
            ),
            attr_factory.create_attribute(
                enums.AttributeType.STATE,
                enums.State.ACTIVE
            )
        ]
        e._get_attributes_from_managed_object = mock.Mock(
            return_value=attrs_list
        )
        payload = payloads.GetAttributeListRequestPayload(
            unique_identifier='1'
        )

        response = e._process_get_attribute_list(payload)
        self.assertIn('Cryptographic Algorithm', response.attribute_names)
        self.assertIn('State', response.attribute_names)

    def test_process_get_attribute_list_permission_denied(self):
        """Test GetAttributeList propagates permission errors."""
        e = self.engine
        e._get_object_with_access_controls = mock.Mock(
            side_effect=exceptions.PermissionDenied("denied")
        )
        payload = payloads.GetAttributeListRequestPayload(
            unique_identifier='1'
        )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "denied",
            e._process_get_attribute_list,
            payload
        )

    def test_process_get_attribute_list_id_placeholder(self):
        """Test GetAttributeList uses the ID placeholder when missing."""
        e = self.engine
        e._id_placeholder = 'placeholder'
        managed_object = mock.Mock()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._get_attributes_from_managed_object = mock.Mock(return_value=[])
        payload = payloads.GetAttributeListRequestPayload()

        response = e._process_get_attribute_list(payload)
        self.assertEqual('placeholder', response.unique_identifier)
        e._get_object_with_access_controls.assert_called_with(
            'placeholder',
            enums.Operation.GET_ATTRIBUTE_LIST
        )

    def test_process_derive_key_pbdkf2_symmetric_key(self):
        """Test DeriveKey derives a symmetric key via PBKDF2."""
        e = self.engine
        keying_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=keying_object
        )
        e._process_template_attribute = mock.Mock(
            return_value={
                'Cryptographic Algorithm':
                    attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.AES
                    ),
                'Cryptographic Length':
                    attributes.CryptographicLength(128)
            }
        )
        crypto_params = attributes.CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )
        derivation_params = attributes.DerivationParameters(
            cryptographic_parameters=crypto_params,
            salt=b'salt',
            iteration_count=1
        )
        e._cryptography_engine.derive_key.return_value = b'\x00' * 16

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=['key-id'],
            derivation_method=enums.DerivationMethod.PBKDF2,
            derivation_parameters=derivation_params,
            template_attribute=core_objects.TemplateAttribute()
        )

        response = e._process_derive_key(payload)
        self.assertIsNotNone(response.unique_identifier)
        e._cryptography_engine.derive_key.assert_called_once()

    def test_process_derive_key_secret_data_hmac_method(self):
        """Test DeriveKey supports HMAC and ENCRYPT for secret data."""
        e = self.engine
        keying_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        secret_object = pie_objects.SecretData(
            b'data',
            enums.SecretDataType.PASSWORD,
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._process_template_attribute = mock.Mock(
            side_effect=lambda _:
                {'Cryptographic Length': attributes.CryptographicLength(64)}
        )
        crypto_params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )
        derivation_params = attributes.DerivationParameters(
            cryptographic_parameters=crypto_params,
            derivation_data=None,
            salt=b'salt',
            iteration_count=1
        )
        e._cryptography_engine.derive_key.return_value = b'\x01' * 8

        for method in [
            enums.DerivationMethod.HMAC,
            enums.DerivationMethod.ENCRYPT
        ]:
            with self.subTest(method=method):
                e._get_object_with_access_controls = mock.Mock(
                    side_effect=[keying_object, secret_object]
                )
                payload = payloads.DeriveKeyRequestPayload(
                    object_type=enums.ObjectType.SECRET_DATA,
                    unique_identifiers=['key-id', 'data-id'],
                    derivation_method=method,
                    derivation_parameters=derivation_params,
                    template_attribute=core_objects.TemplateAttribute()
                )
                response = e._process_derive_key(payload)
                self.assertIsNotNone(response.unique_identifier)

    def test_process_derive_key_missing_length(self):
        """Test DeriveKey rejects missing cryptographic length."""
        e = self.engine
        keying_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=keying_object
        )
        e._process_template_attribute = mock.Mock(return_value={})
        derivation_params = attributes.DerivationParameters(
            cryptographic_parameters=attributes.CryptographicParameters()
        )
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=['key-id'],
            derivation_method=enums.DerivationMethod.PBKDF2,
            derivation_parameters=derivation_params,
            template_attribute=core_objects.TemplateAttribute()
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "cryptographic length",
            e._process_derive_key,
            payload
        )

    def test_process_derive_key_invalid_length_multiple(self):
        """Test DeriveKey rejects cryptographic length not multiple of 8."""
        e = self.engine
        keying_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=keying_object
        )
        e._process_template_attribute = mock.Mock(
            return_value={
                'Cryptographic Length':
                    attributes.CryptographicLength(7)
            }
        )
        derivation_params = attributes.DerivationParameters(
            cryptographic_parameters=attributes.CryptographicParameters()
        )
        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=['key-id'],
            derivation_method=enums.DerivationMethod.PBKDF2,
            derivation_parameters=derivation_params,
            template_attribute=core_objects.TemplateAttribute()
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "multiple of 8",
            e._process_derive_key,
            payload
        )

    def test_process_derive_key_short_output(self):
        """Test DeriveKey rejects derived data shorter than requested."""
        e = self.engine
        keying_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DERIVE_KEY]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=keying_object
        )
        e._process_template_attribute = mock.Mock(
            return_value={
                'Cryptographic Algorithm':
                    attributes.CryptographicAlgorithm(
                        enums.CryptographicAlgorithm.AES
                    ),
                'Cryptographic Length':
                    attributes.CryptographicLength(128)
            }
        )
        derivation_params = attributes.DerivationParameters(
            cryptographic_parameters=attributes.CryptographicParameters()
        )
        e._cryptography_engine.derive_key.return_value = b'\x00' * 8

        payload = payloads.DeriveKeyRequestPayload(
            object_type=enums.ObjectType.SYMMETRIC_KEY,
            unique_identifiers=['key-id'],
            derivation_method=enums.DerivationMethod.PBKDF2,
            derivation_parameters=derivation_params,
            template_attribute=core_objects.TemplateAttribute()
        )

        self.assertRaisesRegex(
            exceptions.CryptographicFailure,
            "specified length",
            e._process_derive_key,
            payload
        )

    def test_process_query_operations_protocol_1_0(self):
        """Test Query returns operations for KMIP 1.0."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(1, 0)
        payload = payloads.QueryRequestPayload(
            query_functions=[enums.QueryFunction.QUERY_OPERATIONS]
        )

        response = e._process_query(payload)
        self.assertIn(enums.Operation.CREATE, response.operations)
        self.assertNotIn(enums.Operation.DISCOVER_VERSIONS, response.operations)
        self.assertNotIn(enums.Operation.ENCRYPT, response.operations)

    def test_process_query_operations_protocol_1_2(self):
        """Test Query returns extended operations for KMIP 1.2."""
        e = self.engine
        e._protocol_version = contents.ProtocolVersion(1, 2)
        payload = payloads.QueryRequestPayload(
            query_functions=[enums.QueryFunction.QUERY_OPERATIONS]
        )

        response = e._process_query(payload)
        self.assertIn(enums.Operation.ENCRYPT, response.operations)
        self.assertIn(enums.Operation.DISCOVER_VERSIONS, response.operations)

    def test_process_query_vendor_info(self):
        """Test Query returns vendor identification."""
        e = self.engine
        payload = payloads.QueryRequestPayload(
            query_functions=[enums.QueryFunction.QUERY_SERVER_INFORMATION]
        )

        response = e._process_query(payload)
        self.assertIn('PyKMIP', response.vendor_identification)

    def test_process_discover_versions_subset(self):
        """Test DiscoverVersions returns supported subset."""
        e = self.engine
        payload = payloads.DiscoverVersionsRequestPayload(
            protocol_versions=[
                contents.ProtocolVersion(1, 4),
                contents.ProtocolVersion(9, 9)
            ]
        )

        response = e._process_discover_versions(payload)
        self.assertEqual(1, len(response.protocol_versions))
        self.assertEqual(1, response.protocol_versions[0].major)
        self.assertEqual(4, response.protocol_versions[0].minor)

    def test_process_discover_versions_empty_list(self):
        """Test DiscoverVersions returns all when request is empty."""
        e = self.engine
        payload = payloads.DiscoverVersionsRequestPayload(
            protocol_versions=[]
        )

        response = e._process_discover_versions(payload)
        self.assertEqual(len(e._protocol_versions), len(response.protocol_versions))

    def test_process_discover_versions_none_supported(self):
        """Test DiscoverVersions returns empty when none supported."""
        e = self.engine
        payload = payloads.DiscoverVersionsRequestPayload(
            protocol_versions=[contents.ProtocolVersion(9, 9)]
        )

        response = e._process_discover_versions(payload)
        self.assertEqual([], response.protocol_versions)

    def test_process_encrypt_aes_cbc_success(self):
        """Test Encrypt succeeds for AES-CBC."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.ENCRYPT]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.PKCS5
        )
        e._cryptography_engine.encrypt.return_value = {
            'cipher_text': b'cipher',
            'iv_nonce': b'iv',
            'auth_tag': None
        }

        payload = payloads.EncryptRequestPayload(
            unique_identifier='1',
            cryptographic_parameters=params,
            data=b'plain',
            iv_counter_nonce=b'iv'
        )

        response = e._process_encrypt(payload)
        self.assertEqual(b'cipher', response.data)
        self.assertEqual(b'iv', response.iv_counter_nonce)

    def test_process_encrypt_missing_parameters(self):
        """Test Encrypt rejects missing cryptographic parameters."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.ENCRYPT]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        payload = payloads.EncryptRequestPayload(
            unique_identifier='1',
            data=b'plain'
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "cryptographic parameters",
            e._process_encrypt,
            payload
        )

    def test_process_encrypt_gcm_missing_iv(self):
        """Test Encrypt propagates errors for missing IVs in GCM."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.ENCRYPT]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            block_cipher_mode=enums.BlockCipherMode.GCM,
            tag_length=128
        )
        e._cryptography_engine.encrypt.side_effect = \
            exceptions.InvalidField("iv required")

        payload = payloads.EncryptRequestPayload(
            unique_identifier='1',
            cryptographic_parameters=params,
            data=b'plain'
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "iv required",
            e._process_encrypt,
            payload
        )

    def test_process_decrypt_aes_gcm_success(self):
        """Test Decrypt succeeds for AES-GCM."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DECRYPT]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            block_cipher_mode=enums.BlockCipherMode.GCM,
            tag_length=128
        )
        e._cryptography_engine.decrypt.return_value = b'plain'

        payload = payloads.DecryptRequestPayload(
            unique_identifier='1',
            cryptographic_parameters=params,
            data=b'cipher',
            iv_counter_nonce=b'iv',
            auth_tag=b'tag'
        )

        response = e._process_decrypt(payload)
        self.assertEqual(b'plain', response.data)

    def test_process_decrypt_missing_parameters(self):
        """Test Decrypt rejects missing cryptographic parameters."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DECRYPT]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        payload = payloads.DecryptRequestPayload(
            unique_identifier='1',
            data=b'cipher'
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "cryptographic parameters",
            e._process_decrypt,
            payload
        )

    def test_process_decrypt_missing_iv(self):
        """Test Decrypt propagates errors for missing IVs."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.DECRYPT]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            block_cipher_mode=enums.BlockCipherMode.GCM,
            tag_length=128
        )
        e._cryptography_engine.decrypt.side_effect = \
            exceptions.InvalidField("iv required")

        payload = payloads.DecryptRequestPayload(
            unique_identifier='1',
            cryptographic_parameters=params,
            data=b'cipher',
            auth_tag=b'tag'
        )

        self.assertRaisesRegex(
            exceptions.InvalidField,
            "iv required",
            e._process_decrypt,
            payload
        )

    def test_process_sign_rsa_success(self):
        """Test Sign succeeds for RSA with different padding/hash options."""
        e = self.engine
        managed_object = self._make_private_key(
            masks=[enums.CryptographicUsageMask.SIGN]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        e._cryptography_engine.sign.return_value = b'signature'

        cases = [
            (enums.PaddingMethod.PKCS1v15, enums.HashingAlgorithm.SHA_256,
             enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION),
            (enums.PaddingMethod.PSS, enums.HashingAlgorithm.SHA_512,
             enums.DigitalSignatureAlgorithm.RSASSA_PSS)
        ]

        for padding, hashing, dsa in cases:
            with self.subTest(padding=padding, hashing=hashing):
                params = attributes.CryptographicParameters(
                    cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                    hashing_algorithm=hashing,
                    padding_method=padding,
                    digital_signature_algorithm=dsa
                )
                payload = payloads.SignRequestPayload(
                    unique_identifier='1',
                    cryptographic_parameters=params,
                    data=b'data'
                )
                response = e._process_sign(payload)
                self.assertEqual(b'signature', response.signature_data)

    def test_process_sign_missing_parameters(self):
        """Test Sign rejects missing cryptographic parameters."""
        e = self.engine
        managed_object = self._make_private_key(
            masks=[enums.CryptographicUsageMask.SIGN]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        payload = payloads.SignRequestPayload(
            unique_identifier='1',
            data=b'data'
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "cryptographic parameters",
            e._process_sign,
            payload
        )

    def test_process_sign_invalid_key_type(self):
        """Test Sign rejects non-private-key objects."""
        e = self.engine
        managed_object = self._make_symmetric_key()
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            padding_method=enums.PaddingMethod.PKCS1v15,
            digital_signature_algorithm=
                enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
        )
        payload = payloads.SignRequestPayload(
            unique_identifier='1',
            cryptographic_parameters=params,
            data=b'data'
        )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "private key",
            e._process_sign,
            payload
        )

    def test_process_signature_verify_valid_invalid(self):
        """Test SignatureVerify returns valid/invalid indicators."""
        e = self.engine
        managed_object = self._make_public_key(
            masks=[enums.CryptographicUsageMask.VERIFY]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            padding_method=enums.PaddingMethod.PKCS1v15,
            digital_signature_algorithm=
                enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
        )

        e._cryptography_engine.verify_signature.return_value = True
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier='1',
            cryptographic_parameters=params,
            data=b'data',
            signature_data=b'sig'
        )
        response = e._process_signature_verify(payload)
        self.assertEqual(enums.ValidityIndicator.VALID,
                         response.validity_indicator)

        e._cryptography_engine.verify_signature.return_value = False
        response = e._process_signature_verify(payload)
        self.assertEqual(enums.ValidityIndicator.INVALID,
                         response.validity_indicator)

    def test_process_signature_verify_missing_parameters(self):
        """Test SignatureVerify rejects missing cryptographic parameters."""
        e = self.engine
        managed_object = self._make_public_key(
            masks=[enums.CryptographicUsageMask.VERIFY]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier='1',
            data=b'data',
            signature_data=b'sig'
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "cryptographic parameters",
            e._process_signature_verify,
            payload
        )

    def test_process_signature_verify_wrong_key_type(self):
        """Test SignatureVerify rejects non-public keys."""
        e = self.engine
        managed_object = self._make_private_key(
            masks=[enums.CryptographicUsageMask.SIGN]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            padding_method=enums.PaddingMethod.PKCS1v15,
            digital_signature_algorithm=
                enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
        )
        payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier='1',
            cryptographic_parameters=params,
            data=b'data',
            signature_data=b'sig'
        )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "public key",
            e._process_signature_verify,
            payload
        )

    def test_process_mac_hmac_sha256_success(self):
        """Test MAC succeeds for HMAC-SHA256."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.MAC_GENERATE]
        )
        managed_object.cryptographic_algorithm = \
            enums.CryptographicAlgorithm.HMAC_SHA256
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.HMAC_SHA256
        )
        e._cryptography_engine.mac.return_value = b'mac'

        payload = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier('1'),
            cryptographic_parameters=params,
            data=core_objects.Data(b'data')
        )
        response = e._process_mac(payload)
        self.assertEqual(b'mac', response.mac_data.value)

    def test_process_mac_invalid_algorithm(self):
        """Test MAC propagates cryptography engine errors for invalid algs."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.MAC_GENERATE]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES
        )
        e._cryptography_engine.mac.side_effect = \
            exceptions.InvalidField("invalid algorithm")

        payload = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier('1'),
            cryptographic_parameters=params,
            data=core_objects.Data(b'data')
        )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "invalid algorithm",
            e._process_mac,
            payload
        )

    def test_process_mac_missing_data(self):
        """Test MAC rejects requests missing data."""
        e = self.engine
        managed_object = self._make_symmetric_key(
            masks=[enums.CryptographicUsageMask.MAC_GENERATE]
        )
        e._get_object_with_access_controls = mock.Mock(
            return_value=managed_object
        )
        params = attributes.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.HMAC_SHA256
        )
        payload = payloads.MACRequestPayload(
            unique_identifier=attributes.UniqueIdentifier('1'),
            cryptographic_parameters=params,
            data=None
        )

        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "No data",
            e._process_mac,
            payload
        )
