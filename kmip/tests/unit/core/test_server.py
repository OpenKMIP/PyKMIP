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

from testtools import TestCase

from kmip.core.attributes import CryptographicAlgorithm
from kmip.core.attributes import CryptographicLength
from kmip.core.attributes import CryptographicUsageMask
from kmip.core.attributes import UniqueIdentifier
from kmip.core.attributes import ObjectType
from kmip.core.attributes import Name

from kmip.core.enums import AttributeType
from kmip.core.enums import CryptographicAlgorithm as CryptoAlgorithmEnum
from kmip.core.enums import CryptographicUsageMask as CryptoUsageMaskEnum
from kmip.core.enums import KeyCompressionType as KeyCompressionTypeEnum
from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import ObjectType as ObjectTypeEnum
from kmip.core.enums import ResultReason
from kmip.core.enums import ResultStatus
from kmip.core.enums import NameType

from kmip.core.factories.attributes import AttributeFactory

from kmip.core.messages.contents import KeyCompressionType
from kmip.core.misc import KeyFormatType

from kmip.core.objects import KeyBlock
from kmip.core.objects import KeyMaterial
from kmip.core.objects import KeyValue
from kmip.core.objects import TemplateAttribute

from kmip.core.secrets import SymmetricKey
from kmip.core.server import KMIPImpl


class TestKMIPServer(TestCase):

    def setUp(self):
        super(TestKMIPServer, self).setUp()
        self.kmip = KMIPImpl()
        self.algorithm_name = CryptoAlgorithmEnum.AES
        self.key_length = 256
        self.key = bytearray(range(0, 32))
        self.usage_mask = CryptoUsageMaskEnum.ENCRYPT.value |\
            CryptoUsageMaskEnum.DECRYPT.value

    def tearDown(self):
        super(TestKMIPServer, self).tearDown()

    def test_create(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        attributes = self._get_attrs()
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.create(obj_type, template_attribute)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')

    def test_create_no_length(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        attributes = self._get_attrs()[0:2]
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.create(obj_type, template_attribute)
        self.assertNotEqual(None, res, 'result is None')
        attrs = res.template_attribute.attributes
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')
        self.assertTrue(self._check_attr_exists(attributes[2], attrs),
                        'length attribute not returned')

    def test_create_no_alg(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        attributes = [self._get_attrs()[1]]
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.create(obj_type, template_attribute)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(
            ResultStatus.OPERATION_FAILED,
            res.result_status.value,
            'result status did not return failed')

    def test_create_no_usage_mask(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        attributes = [self._get_attrs()[0]]
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.create(obj_type, template_attribute)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(
            ResultStatus.OPERATION_FAILED,
            res.result_status.value,
            'result status did not return failed')

    def test_register(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')

    def test_register_attrs_in_key_value(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.cryptographic_algorithm = None
        key.key_block.cryptographic_length = None
        key.key_block.key_value.attributes = self._get_attrs()
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')

    def test_register_attrs_in_template(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.cryptographic_algorithm = None
        key.key_block.cryptographic_length = None
        key.key_block.key_value.attributes = []
        attributes = self._get_attrs()
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')

    def test_register_no_alg(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.cryptographic_algorithm = None
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_alg_in_key_value_and_key_block(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.key_value.attributes = [self._get_alg_attr()]
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.INDEX_OUT_OF_BOUNDS,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_alg_in_template_and_key_block(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        attributes = [self._get_alg_attr()]
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.INDEX_OUT_OF_BOUNDS,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_alg_in_template_and_key_value(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.cryptographic_algorithm = None
        key.key_block.key_value.attributes = [self._get_alg_attr()]
        attributes = [self._get_alg_attr()]
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.INDEX_OUT_OF_BOUNDS,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_invalid_alg(self):
        unsupported_algs = (CryptoAlgorithmEnum.RSA,
                            CryptoAlgorithmEnum.DSA,
                            CryptoAlgorithmEnum.ECDSA,
                            CryptoAlgorithmEnum.HMAC_SHA1,
                            CryptoAlgorithmEnum.HMAC_SHA224,
                            CryptoAlgorithmEnum.HMAC_SHA256,
                            CryptoAlgorithmEnum.HMAC_SHA384,
                            CryptoAlgorithmEnum.HMAC_SHA512,
                            CryptoAlgorithmEnum.HMAC_MD5,
                            CryptoAlgorithmEnum.DH,
                            CryptoAlgorithmEnum.ECDH,
                            CryptoAlgorithmEnum.ECMQV,
                            CryptoAlgorithmEnum.BLOWFISH,
                            CryptoAlgorithmEnum.CAMELLIA,
                            CryptoAlgorithmEnum.CAST5,
                            CryptoAlgorithmEnum.IDEA,
                            CryptoAlgorithmEnum.MARS,
                            CryptoAlgorithmEnum.RC2,
                            CryptoAlgorithmEnum.RC4,
                            CryptoAlgorithmEnum.RC5,
                            CryptoAlgorithmEnum.SKIPJACK,
                            CryptoAlgorithmEnum.TWOFISH)
        for alg in unsupported_algs:
            obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
            key = self._get_symmetric_key()
            key.key_block.cryptographic_algorithm = CryptographicAlgorithm(alg)
            attributes = []
            template_attribute = TemplateAttribute(attributes=attributes)
            res = self.kmip.register(obj_type, template_attribute, key)
            self.assertEqual(ResultStatus.OPERATION_FAILED,
                             res.result_status.value,
                             'result status did not return failed')
            self.assertEqual(ResultReason.INVALID_FIELD,
                             res.result_reason.value,
                             'result reason did not match')

    def test_register_no_length(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.cryptographic_length = None
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_length_in_key_value_and_key_block(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.key_value.attributes = [self._get_length_attr()]
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.INDEX_OUT_OF_BOUNDS,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_length_in_template_and_key_block(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        attributes = [self._get_length_attr()]
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.INDEX_OUT_OF_BOUNDS,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_length_in_template_and_key_value(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.cryptographic_length = None
        key.key_block.key_value.attributes = [self._get_length_attr()]
        attributes = [self._get_length_attr()]
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.INDEX_OUT_OF_BOUNDS,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_invalid_length(self):
        unsupported_lens = (-1, 0, 2048, 5, 18)
        for len in unsupported_lens:
            obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
            key = self._get_symmetric_key()
            key.key_block.cryptographic_length = CryptographicLength(len)
            attributes = []
            template_attribute = TemplateAttribute(attributes=attributes)
            res = self.kmip.register(obj_type, template_attribute, key)
            self.assertEqual(ResultStatus.OPERATION_FAILED,
                             res.result_status.value,
                             'result status did not return failed')
            self.assertEqual(ResultReason.INVALID_FIELD,
                             res.result_reason.value,
                             'result reason did not match')

    def test_register_no_usage_mask(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        key = self._get_symmetric_key()
        key.key_block.key_value.attributes = []
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_no_object_type(self):
        obj_type = None
        key = self._get_symmetric_key()
        attributes = []
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.register(obj_type, template_attribute, key)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                         res.result_reason.value,
                         'result reason did not match')

    def test_register_unsupported_object_type(self):
        unsupported_types = (ObjectTypeEnum.CERTIFICATE,
                             ObjectTypeEnum.PUBLIC_KEY,
                             ObjectTypeEnum.PRIVATE_KEY,
                             ObjectTypeEnum.SPLIT_KEY,
                             ObjectTypeEnum.TEMPLATE,
                             ObjectTypeEnum.SECRET_DATA,
                             ObjectTypeEnum.OPAQUE_DATA)
        for unsupported_type in unsupported_types:
            obj_type = ObjectType(unsupported_type)
            key = self._get_symmetric_key()
            attributes = []
            template_attribute = TemplateAttribute(attributes=attributes)
            res = self.kmip.register(obj_type, template_attribute, key)
            self.assertNotEqual(None, res, 'result is None')
            self.assertEqual(ResultStatus.OPERATION_FAILED,
                             res.result_status.value,
                             'result status did not return failed')
            self.assertEqual(ResultReason.INVALID_FIELD,
                             res.result_reason.value,
                             'result reason did not match')

    def test_register_object_type_mismatch(self):
        unsupported_types = (ObjectTypeEnum.CERTIFICATE,
                             ObjectTypeEnum.PUBLIC_KEY,
                             ObjectTypeEnum.PRIVATE_KEY,
                             ObjectTypeEnum.SPLIT_KEY,
                             ObjectTypeEnum.TEMPLATE,
                             ObjectTypeEnum.SECRET_DATA,
                             ObjectTypeEnum.OPAQUE_DATA)
        for unsupported_type in unsupported_types:
            obj_type = ObjectType(unsupported_type)
            key = self._get_symmetric_key()
            attributes = []
            template_attribute = TemplateAttribute(attributes=attributes)
            res = self.kmip.register(obj_type, template_attribute, key)
            self.assertNotEqual(None, res, 'result is None')
            self.assertEqual(ResultStatus.OPERATION_FAILED,
                             res.result_status.value,
                             'result status did not return failed')
            self.assertEqual(ResultReason.INVALID_FIELD,
                             res.result_reason.value,
                             'result reason did not match')

    def test_get(self):
        uuid = self._create()
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        res = self.kmip.get(uuid, key_format_type)
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')

    def test_get_no_key_format_type(self):
        uuid = self._create()
        res = self.kmip.get(uuid, None)
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')

    def test_get_unknown(self):
        uuids = ('some random string', UniqueIdentifier('no key here'))
        for uuid in uuids:
            key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
            res = self.kmip.get(uuid, key_format_type)
            self.assertEqual(ResultStatus.OPERATION_FAILED,
                             res.result_status.value,
                             'result status did not return failed')
            self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                             res.result_reason.value,
                             'result reason did not match')

    def test_get_no_uuid(self):
        self._create()
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        res = self.kmip.get(None, key_format_type)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')

    def test_get_with_key_compression(self):
        uuid = self._create()
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        key_compression = KeyCompressionType(KeyCompressionTypeEnum.
                                             EC_PUBLIC_KEY_TYPE_UNCOMPRESSED)
        res = self.kmip.get(uuid, key_format_type, key_compression)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.KEY_COMPRESSION_TYPE_NOT_SUPPORTED,
                         res.result_reason.value,
                         'result reason did not match')

    def test_destroy(self):
        uuid = self._create()
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        res = self.kmip.get(uuid, key_format_type)
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')
        res = self.kmip.destroy(uuid)
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')
        res = self.kmip.destroy(uuid)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                         res.result_reason.value,
                         'result reason did not match')

    def test_destroy_no_uuid(self):
        res = self.kmip.destroy(None)
        self.assertEqual(ResultStatus.OPERATION_FAILED,
                         res.result_status.value,
                         'result status did not return failed')
        self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                         res.result_reason.value,
                         'result reason did not match')

    def test_destroy_unknown(self):
        uuids = ('some random string', UniqueIdentifier('no key here'))
        for uuid in uuids:
            key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
            res = self.kmip.get(uuid, key_format_type)
            self.assertEqual(ResultStatus.OPERATION_FAILED,
                             res.result_status.value,
                             'result status did not return failed')
            res = self.kmip.destroy(uuid)
            self.assertEqual(ResultStatus.OPERATION_FAILED,
                             res.result_status.value,
                             'result status did not return failed')
            self.assertEqual(ResultReason.ITEM_NOT_FOUND,
                             res.result_reason.value,
                             'result reason did not match')

    def _create(self):
        obj_type = ObjectType(ObjectTypeEnum.SYMMETRIC_KEY)
        attributes = self._get_attrs()
        template_attribute = TemplateAttribute(attributes=attributes)
        res = self.kmip.create(obj_type, template_attribute)
        self.assertNotEqual(None, res, 'result is None')
        self.assertEqual(ResultStatus.SUCCESS, res.result_status.value,
                         'result status did not return success')
        return res.uuid

    def _get_symmetric_key(self):
        # only need usage attribute
        attrs = [self._get_attrs()[1]]
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        key_material = KeyMaterial(self.key)
        key_value = KeyValue(key_material, attrs)
        crypto_alg = CryptographicAlgorithm(self.algorithm_name)
        crypto_length = CryptographicLength(self.key_length)
        usage = CryptographicUsageMask(self.usage_mask)
        key_block = KeyBlock(key_format_type, None, key_value, crypto_alg,
                             crypto_length, usage)
        return SymmetricKey(key_block)

    def _get_attrs(self):
        attr_factory = AttributeFactory()
        algorithm = self._get_alg_attr(self.algorithm_name)
        length = self._get_length_attr(self.key_length)
        attribute_type = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        mask_flags = [CryptoUsageMaskEnum.ENCRYPT,
                      CryptoUsageMaskEnum.DECRYPT]
        usage_mask = attr_factory.create_attribute(attribute_type,
                                                   mask_flags)
        name_value = Name.NameValue(value='TESTNAME')
        name_type = Name.NameType(value=NameType.UNINTERPRETED_TEXT_STRING)
        value = Name.create(name_value, name_type)
        nameattr = attr_factory.create_attribute(AttributeType.NAME, value)
        return [algorithm, usage_mask, length, nameattr]

    def _get_alg_attr(self, alg=None):
        if alg is None:
            alg = self.algorithm_name
        attr_factory = AttributeFactory()
        attribute_type = AttributeType.CRYPTOGRAPHIC_ALGORITHM
        return attr_factory.create_attribute(attribute_type, alg)

    def _get_length_attr(self, length=None):
        if length is None:
            length = self.key_length
        attr_factory = AttributeFactory()
        attribute_type = AttributeType.CRYPTOGRAPHIC_LENGTH
        return attr_factory.create_attribute(attribute_type, length)

    def _check_attr_exists(self, attr_expected, attributes):
        for attribute in attributes:
            if attribute.attribute_name.value ==\
                    attr_expected.attribute_name.value:
                return attribute.attribute_value.value ==\
                    attr_expected.attribute_value.value
        return False

    def test_locate(self):
        self._create()

        name_value = Name.NameValue(value='TESTNAME')
        name_type = Name.NameType(value=NameType.UNINTERPRETED_TEXT_STRING)
        value = Name.create(name_value, name_type)

        attr_factory = AttributeFactory()
        nameattr = attr_factory.create_attribute(AttributeType.NAME, value)

        attrs = [nameattr]
        res = self.kmip.locate(attributes=attrs)
        self.assertEqual(
            ResultStatus.OPERATION_FAILED,
            res.result_status.value,
            'locate result status did not return success')
