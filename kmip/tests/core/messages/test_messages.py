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

from kmip.core.factories.keys import KeyFactory
from kmip.core.factories.secrets import SecretFactory
from kmip.core.factories.attributes import AttributeFactory

from kmip.core import attributes as attr
from kmip.core.attributes import ApplicationSpecificInformation
from kmip.core.attributes import ContactInformation
from kmip.core.attributes import Name
from kmip.core.attributes import ObjectGroup

from kmip.core import enums
from kmip.core.enums import AttributeType
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import NameType
from kmip.core.enums import ObjectType

from kmip.core import errors
from kmip.core.errors import ErrorStrings

from kmip.core import objects

from kmip.core.keys import RawKey

from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core.messages import operations

from kmip.core.messages.operations import DestroyRequestPayload
from kmip.core.messages.operations import RegisterRequestPayload
from kmip.core.messages.operations import DestroyResponsePayload
from kmip.core.messages.operations import RegisterResponsePayload

from kmip.core.primitives import TextString

from kmip.core.secrets import SymmetricKey
from kmip.core.secrets import Template

from kmip.core import utils
from kmip.core.utils import BytearrayStream


class TestRequestMessage(TestCase):

    def setUp(self):
        super(TestRequestMessage, self).setUp()
        self.stream = BytearrayStream()
        self.attribute_factory = AttributeFactory()
        self.msg = errors.ErrorStrings.BAD_EXP_RECV
        self.create = (
            '\x42\x00\x78\x01\x00\x00\x01\x20\x42\x00\x77\x01\x00\x00\x00\x38'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\xD8'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            '\x42\x00\x79\x01\x00\x00\x00\xC0\x42\x00\x57\x05\x00\x00\x00\x04'
            '\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x91\x01\x00\x00\x00\xA8'
            '\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x17'
            '\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            '\x67\x6F\x72\x69\x74\x68\x6D\x00\x42\x00\x0B\x05\x00\x00\x00\x04'
            '\x00\x00\x00\x03\x00\x00\x00\x00\x42\x00\x08\x01\x00\x00\x00\x30'
            '\x42\x00\x0A\x07\x00\x00\x00\x14\x43\x72\x79\x70\x74\x6F\x67\x72'
            '\x61\x70\x68\x69\x63\x20\x4C\x65\x6E\x67\x74\x68\x00\x00\x00\x00'
            '\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            '\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x18'
            '\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            '\x61\x67\x65\x20\x4D\x61\x73\x6B\x42\x00\x0B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x0C\x00\x00\x00\x00')
        self.register = (
            '\x42\x00\x78\x01\x00\x00\x01\xC8\x42\x00\x77\x01\x00\x00\x00\x38'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x01\x80'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            '\x42\x00\x79\x01\x00\x00\x01\x68\x42\x00\x57\x05\x00\x00\x00\x04'
            '\x00\x00\x00\x06\x00\x00\x00\x00\x42\x00\x91\x01\x00\x00\x00\x00'
            '\x42\x00\x90\x01\x00\x00\x01\x48\x42\x00\x08\x01\x00\x00\x00\x28'
            '\x42\x00\x0A\x07\x00\x00\x00\x0C\x4F\x62\x6A\x65\x63\x74\x20\x47'
            '\x72\x6F\x75\x70\x00\x00\x00\x00\x42\x00\x0B\x07\x00\x00\x00\x06'
            '\x47\x72\x6F\x75\x70\x31\x00\x00\x42\x00\x08\x01\x00\x00\x00\x58'
            '\x42\x00\x0A\x07\x00\x00\x00\x20\x41\x70\x70\x6C\x69\x63\x61\x74'
            '\x69\x6F\x6E\x20\x53\x70\x65\x63\x69\x66\x69\x63\x20\x49\x6E\x66'
            '\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x42\x00\x0B\x01\x00\x00\x00\x28'
            '\x42\x00\x03\x07\x00\x00\x00\x03\x73\x73\x6C\x00\x00\x00\x00\x00'
            '\x42\x00\x02\x07\x00\x00\x00\x0F\x77\x77\x77\x2E\x65\x78\x61\x6D'
            '\x70\x6C\x65\x2E\x63\x6F\x6D\x00\x42\x00\x08\x01\x00\x00\x00\x30'
            '\x42\x00\x0A\x07\x00\x00\x00\x13\x43\x6F\x6E\x74\x61\x63\x74\x20'
            '\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x00\x00\x00\x00\x00'
            '\x42\x00\x0B\x07\x00\x00\x00\x03\x4A\x6F\x65\x00\x00\x00\x00\x00'
            '\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x09'
            '\x78\x2D\x50\x75\x72\x70\x6F\x73\x65\x00\x00\x00\x00\x00\x00\x00'
            '\x42\x00\x0B\x07\x00\x00\x00\x0D\x64\x65\x6D\x6F\x6E\x73\x74\x72'
            '\x61\x74\x69\x6F\x6E\x00\x00\x00\x42\x00\x08\x01\x00\x00\x00\x40'
            '\x42\x00\x0A\x07\x00\x00\x00\x04\x4E\x61\x6D\x65\x00\x00\x00\x00'
            '\x42\x00\x0B\x01\x00\x00\x00\x28\x42\x00\x55\x07\x00\x00\x00\x09'
            '\x54\x65\x6D\x70\x6C\x61\x74\x65\x31\x00\x00\x00\x00\x00\x00\x00'
            '\x42\x00\x54\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00')
        self.get = (
            '\x42\x00\x78\x01\x00\x00\x00\x90\x42\x00\x77\x01\x00\x00\x00\x38'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\x48'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00'
            '\x42\x00\x79\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            '\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            '\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            '\x33\x30\x33\x38\x00\x00\x00\x00')
        self.destroy = (
            '\x42\x00\x78\x01\x00\x00\x00\x90\x42\x00\x77\x01\x00\x00\x00\x38'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\x48'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x00'
            '\x42\x00\x79\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            '\x66\x62\x34\x62\x35\x62\x39\x63\x2D\x36\x31\x38\x38\x2D\x34\x63'
            '\x36\x33\x2D\x38\x31\x34\x32\x2D\x66\x65\x39\x63\x33\x32\x38\x31'
            '\x32\x39\x66\x63\x00\x00\x00\x00')

    def tearDown(self):
        super(TestRequestMessage, self).tearDown()

    def test_create_request_read(self):
        self.stream = BytearrayStream(self.create)

        request_message = messages.RequestMessage()
        request_message.read(self.stream)

        request_header = request_message.request_header
        msg = "Bad request header type: expected {0}, received{1}"
        self.assertIsInstance(request_header, messages.RequestHeader,
                              msg.format(messages.RequestHeader,
                                         type(request_header)))

        protocol_version = request_header.protocol_version
        msg = "Bad protocol version type: expected {0}, received {1}"
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              msg.format(contents.ProtocolVersion,
                                         type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        msg = "Bad protocol version major type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version major value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_major.value,
                         msg.format(1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        msg = "Bad protocol version minor type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version minor value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_minor.value,
                         msg.format(1, protocol_version_minor.value))

        batch_count = request_header.batch_count
        msg = "Bad batch count type: expected {0}, received {1}"
        self.assertIsInstance(batch_count, contents.BatchCount,
                              msg.format(contents.BatchCount,
                                         type(batch_count)))
        msg = "Bad batch count value: expected {0}, received {1}"
        self.assertEqual(1, batch_count.value,
                         msg.format(1, batch_count.value))

        batch_items = request_message.batch_items
        msg = "Bad batch items type: expected {0}, received {1}"
        self.assertIsInstance(batch_items, list,
                              msg.format(list, type(batch_items)))
        self.assertEquals(1, len(batch_items),
                          self.msg.format('batch items', 'length',
                                          1, len(batch_items)))

        batch_item = batch_items[0]
        msg = "Bad batch item type: expected {0}, received {1}"
        self.assertIsInstance(batch_item, messages.RequestBatchItem,
                              msg.format(messages.RequestBatchItem,
                                         type(batch_item)))

        operation = batch_item.operation
        msg = "Bad operation type: expected {0}, received {1}"
        self.assertIsInstance(operation, contents.Operation,
                              msg.format(contents.Operation,
                                         type(operation)))
        msg = "Bad operation value: expected {0}, received {1}"
        self.assertEqual(enums.Operation.CREATE, operation.enum,
                         msg.format(enums.Operation.CREATE,
                                    operation.enum))

        request_payload = batch_item.request_payload
        msg = "Bad request payload type: expected {0}, received {1}"
        self.assertIsInstance(request_payload,
                              operations.CreateRequestPayload,
                              msg.format(operations.CreateRequestPayload,
                                         type(request_payload)))

        object_type = request_payload.object_type
        msg = "Bad object type type: expected {0}, received {1}"
        self.assertIsInstance(object_type, attr.ObjectType,
                              msg.format(attr.ObjectType,
                                         type(object_type)))
        msg = "Bad object type value: expected {0}, received {1}"
        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, object_type.enum,
                         msg.format(enums.ObjectType.SYMMETRIC_KEY,
                                    object_type.enum))

        template_attribute = request_payload.template_attribute
        msg = "Bad template attribute type: expected {0}, received {1}"
        self.assertIsInstance(template_attribute,
                              objects.TemplateAttribute,
                              msg.format(objects.TemplateAttribute,
                                         type(template_attribute)))

        attributes = template_attribute.attributes
        self.assertIsInstance(attributes, list,
                              self.msg.format('attributes', 'type',
                                              list, type(attributes)))
        self.assertEquals(3, len(attributes),
                          self.msg.format('attributes', 'length',
                                          3, len(attributes)))

        attribute_a = attributes[0]
        self.assertIsInstance(attribute_a, objects.Attribute,
                              self.msg.format('attribute', 'type',
                                              objects.Attribute,
                                              type(attribute_a)))

        attribute_name = attribute_a.attribute_name
        self.assertIsInstance(attribute_name, objects.Attribute.AttributeName,
                              self.msg.format('attribute name', 'type',
                                              objects.Attribute.AttributeName,
                                              type(attribute_name)))
        self.assertEquals('Cryptographic Algorithm', attribute_name.value,
                          self.msg.format('attribute name', 'value',
                                          'Cryptographic Algorithm',
                                          attribute_name.value))

        attribute_value = attribute_a.attribute_value
        exp_type = attr.CryptographicAlgorithm
        rcv_type = type(attribute_value)
        self.assertIsInstance(attribute_value, exp_type,
                              self.msg.format('attribute value', 'type',
                                              exp_type, rcv_type))
        self.assertEquals(attribute_value.enum,
                          enums.CryptographicAlgorithm.AES,
                          self.msg.format('cryptographic algorithm', 'value',
                                          enums.CryptographicAlgorithm.AES,
                                          attribute_value.enum))

        attribute_b = attributes[1]
        self.assertIsInstance(attribute_b, objects.Attribute,
                              self.msg.format('attribute', 'type',
                                              objects.Attribute,
                                              type(attribute_b)))

        attribute_name = attribute_b.attribute_name
        self.assertIsInstance(attribute_name, objects.Attribute.AttributeName,
                              self.msg.format('attribute name', 'type',
                                              objects.Attribute.AttributeName,
                                              type(attribute_name)))
        self.assertEquals('Cryptographic Length', attribute_name.value,
                          self.msg.format('attribute name', 'value',
                                          'Cryptographic Length',
                                          attribute_name.value))

        attribute_value = attribute_b.attribute_value
        exp_type = attr.CryptographicLength
        rcv_type = type(attribute_value)
        self.assertIsInstance(attribute_value, exp_type,
                              self.msg.format('attribute value', 'type',
                                              exp_type, rcv_type))
        self.assertEquals(attribute_value.value, 128,
                          self.msg.format('cryptographic length', 'value',
                                          128, attribute_value.value))

        attribute_c = attributes[2]
        self.assertIsInstance(attribute_c, objects.Attribute,
                              self.msg.format('attribute', 'type',
                                              objects.Attribute,
                                              type(attribute_b)))

        attribute_name = attribute_c.attribute_name
        self.assertIsInstance(attribute_name, objects.Attribute.AttributeName,
                              self.msg.format('attribute name', 'type',
                                              objects.Attribute.AttributeName,
                                              type(attribute_name)))
        self.assertEquals('Cryptographic Usage Mask', attribute_name.value,
                          self.msg.format('attribute name', 'value',
                                          'Cryptographic Usage Mask',
                                          attribute_name.value))

        attribute_value = attribute_c.attribute_value
        exp_type = attr.CryptographicUsageMask
        rcv_type = type(attribute_value)
        self.assertIsInstance(attribute_value, exp_type,
                              self.msg.format('attribute value', 'type',
                                              exp_type, rcv_type))
        flag_encrypt = CryptographicUsageMask.ENCRYPT
        flag_decrypt = CryptographicUsageMask.DECRYPT
        exp_value = flag_encrypt.value | flag_decrypt.value
        self.assertEquals(attribute_value.value, exp_value,
                          self.msg.format('cryptographic usage mask', 'value',
                                          exp_value, attribute_value.value))

    def test_create_request_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        batch_count = contents.BatchCount(1)
        request_header = messages.RequestHeader(protocol_version=prot_ver,
                                                batch_count=batch_count)

        operation = contents.Operation(enums.Operation.CREATE)
        object_type = attr.ObjectType(enums.ObjectType.SYMMETRIC_KEY)

        name = AttributeType.CRYPTOGRAPHIC_ALGORITHM
        value = CryptographicAlgorithm.AES
        attr_a = self.attribute_factory.create_attribute(name, value)

        name = AttributeType.CRYPTOGRAPHIC_LENGTH
        value = 128
        attr_b = self.attribute_factory.create_attribute(name, value)

        name = AttributeType.CRYPTOGRAPHIC_USAGE_MASK
        value = [CryptographicUsageMask.ENCRYPT,
                 CryptographicUsageMask.DECRYPT]
        attr_c = self.attribute_factory.create_attribute(name, value)

        temp_attr = objects.TemplateAttribute(attributes=[attr_a, attr_b,
                                                          attr_c])
        req_pl = operations.CreateRequestPayload(object_type=object_type,
                                                 template_attribute=temp_attr)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)
        req_message = messages.RequestMessage(request_header=request_header,
                                              batch_items=[batch_item])
        req_message.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.create)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('request message', 'write',
                                         len_exp, len_rcv))

        msg = "Bad request message write: encoding mismatch"
        self.assertEqual(self.create, result, msg)

    def test_get_request_read(self):
        self.stream = BytearrayStream(self.get)

        request_message = messages.RequestMessage()
        request_message.read(self.stream)

        request_header = request_message.request_header
        msg = "Bad request header type: expected {0}, received{0}"
        self.assertIsInstance(request_header, messages.RequestHeader,
                              msg.format(messages.RequestHeader,
                                         type(request_header)))

        protocol_version = request_header.protocol_version
        msg = "Bad protocol version type: expected {0}, received {1}"
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              msg.format(contents.ProtocolVersion,
                                         type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        msg = "Bad protocol version major type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version major value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_major.value,
                         msg.format(1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        msg = "Bad protocol version minor type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version minor value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_minor.value,
                         msg.format(1, protocol_version_minor.value))

        batch_count = request_header.batch_count
        msg = "Bad batch count type: expected {0}, received {1}"
        self.assertIsInstance(batch_count, contents.BatchCount,
                              msg.format(contents.BatchCount,
                                         type(batch_count)))
        msg = "Bad batch count value: expected {0}, received {1}"
        self.assertEqual(1, batch_count.value,
                         msg.format(1, batch_count.value))

        batch_items = request_message.batch_items
        msg = "Bad batch items type: expected {0}, received {1}"
        self.assertIsInstance(batch_items, list,
                              msg.format(list, type(batch_items)))
        self.assertEquals(1, len(batch_items),
                          self.msg.format('batch items', 'length',
                                          1, len(batch_items)))

        batch_item = batch_items[0]
        msg = "Bad batch item type: expected {0}, received {1}"
        self.assertIsInstance(batch_item, messages.RequestBatchItem,
                              msg.format(messages.RequestBatchItem,
                                         type(batch_item)))

        operation = batch_item.operation
        msg = "Bad operation type: expected {0}, received {1}"
        self.assertIsInstance(operation, contents.Operation,
                              msg.format(contents.Operation,
                                         type(operation)))
        msg = "Bad operation value: expected {0}, received {1}"
        self.assertEqual(enums.Operation.GET, operation.enum,
                         msg.format(enums.Operation.GET,
                                    operation.enum))

        request_payload = batch_item.request_payload
        msg = "Bad request payload type: expected {0}, received {1}"
        self.assertIsInstance(request_payload,
                              operations.GetRequestPayload,
                              msg.format(operations.GetRequestPayload,
                                         type(request_payload)))

        unique_identifier = request_payload.unique_identifier
        msg = "Bad unique identifier type: expected {0}, received {1}"
        self.assertIsInstance(unique_identifier, attr.UniqueIdentifier,
                              msg.format(attr.UniqueIdentifier,
                                         type(unique_identifier)))
        msg = "Bad unique identifier value: expected {0}, received {1}"
        self.assertEqual('49a1ca88-6bea-4fb2-b450-7e58802c3038',
                         unique_identifier.value,
                         msg.format('49a1ca88-6bea-4fb2-b450-7e58802c3038',
                                    unique_identifier.value))

    def test_get_request_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        batch_count = contents.BatchCount(1)
        req_header = messages.RequestHeader(protocol_version=prot_ver,
                                            batch_count=batch_count)

        operation = contents.Operation(enums.Operation.GET)

        uuid = attr.UniqueIdentifier('49a1ca88-6bea-4fb2-b450-7e58802c3038')
        request_payload = operations.GetRequestPayload(unique_identifier=uuid)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=request_payload)
        request_message = messages.RequestMessage(request_header=req_header,
                                                  batch_items=[batch_item])
        request_message.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.get)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('request message', 'write',
                                         len_exp, len_rcv))

        msg = "Bad request message write: encoding mismatch"
        self.assertEqual(self.get, result, msg)

    def test_destroy_request_read(self):
        self.stream = BytearrayStream(self.destroy)

        request_message = messages.RequestMessage()
        request_message.read(self.stream)

        request_header = request_message.request_header
        msg = "Bad request header type: expected {0}, received{0}"
        self.assertIsInstance(request_header, messages.RequestHeader,
                              msg.format(messages.RequestHeader,
                                         type(request_header)))

        protocol_version = request_header.protocol_version
        msg = "Bad protocol version type: expected {0}, received {1}"
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              msg.format(contents.ProtocolVersion,
                                         type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        msg = "Bad protocol version major type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version major value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_major.value,
                         msg.format(1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        msg = "Bad protocol version minor type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version minor value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_minor.value,
                         msg.format(1, protocol_version_minor.value))

        batch_count = request_header.batch_count
        msg = "Bad batch count type: expected {0}, received {1}"
        self.assertIsInstance(batch_count, contents.BatchCount,
                              msg.format(contents.BatchCount,
                                         type(batch_count)))
        msg = "Bad batch count value: expected {0}, received {1}"
        self.assertEqual(1, batch_count.value,
                         msg.format(1, batch_count.value))

        batch_items = request_message.batch_items
        msg = "Bad batch items type: expected {0}, received {1}"
        self.assertIsInstance(batch_items, list,
                              msg.format(list, type(batch_items)))
        self.assertEquals(1, len(batch_items),
                          self.msg.format('batch items', 'length',
                                          1, len(batch_items)))

        batch_item = batch_items[0]
        msg = "Bad batch item type: expected {0}, received {1}"
        self.assertIsInstance(batch_item, messages.RequestBatchItem,
                              msg.format(messages.RequestBatchItem,
                                         type(batch_item)))

        operation = batch_item.operation
        msg = "Bad operation type: expected {0}, received {1}"
        self.assertIsInstance(operation, contents.Operation,
                              msg.format(contents.Operation,
                                         type(operation)))
        msg = "Bad operation value: expected {0}, received {1}"
        exp_value = enums.Operation.DESTROY
        rcv_value = operation.enum
        self.assertEqual(exp_value, rcv_value,
                         msg.format(exp_value, rcv_value))

        request_payload = batch_item.request_payload
        msg = "Bad request payload type: expected {0}, received {1}"
        exp_type = operations.DestroyRequestPayload
        rcv_type = type(request_payload)
        self.assertIsInstance(request_payload, exp_type,
                              msg.format(exp_type, rcv_type))

        unique_identifier = request_payload.unique_identifier
        msg = "Bad unique identifier type: expected {0}, received {1}"
        self.assertIsInstance(unique_identifier, attr.UniqueIdentifier,
                              msg.format(attr.UniqueIdentifier,
                                         type(unique_identifier)))
        msg = "Bad unique identifier value: expected {0}, received {1}"
        exp_value = 'fb4b5b9c-6188-4c63-8142-fe9c328129fc'
        rcv_value = unique_identifier.value
        self.assertEqual(exp_value, rcv_value,
                         msg.format(exp_value, rcv_value))

    def test_destroy_request_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        batch_count = contents.BatchCount(1)
        req_header = messages.RequestHeader(protocol_version=prot_ver,
                                            batch_count=batch_count)

        operation = contents.Operation(enums.Operation.DESTROY)

        uuid = attr.UniqueIdentifier('fb4b5b9c-6188-4c63-8142-fe9c328129fc')
        request_payload = DestroyRequestPayload(unique_identifier=uuid)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=request_payload)
        request_message = messages.RequestMessage(request_header=req_header,
                                                  batch_items=[batch_item])
        request_message.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.destroy)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('request message', 'write',
                                         len_exp, len_rcv))

        msg = "Bad request message write: encoding mismatch"
        self.assertEqual(self.destroy, result, msg)

    def test_register_request_read(self):
        self.stream = BytearrayStream(self.register)

        request_message = messages.RequestMessage()
        request_message.read(self.stream)

        request_header = request_message.request_header
        msg = "Bad request header type: expected {0}, received{0}"
        self.assertIsInstance(request_header, messages.RequestHeader,
                              msg.format(messages.RequestHeader,
                                         type(request_header)))

        protocol_version = request_header.protocol_version
        msg = "Bad protocol version type: expected {0}, received {1}"
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              msg.format(contents.ProtocolVersion,
                                         type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        msg = "Bad protocol version major type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version major value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_major.value,
                         msg.format(1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        msg = "Bad protocol version minor type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version minor value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_minor.value,
                         msg.format(1, protocol_version_minor.value))

        batch_count = request_header.batch_count
        msg = "Bad batch count type: expected {0}, received {1}"
        self.assertIsInstance(batch_count, contents.BatchCount,
                              msg.format(contents.BatchCount,
                                         type(batch_count)))
        msg = "Bad batch count value: expected {0}, received {1}"
        self.assertEqual(1, batch_count.value,
                         msg.format(1, batch_count.value))

        batch_items = request_message.batch_items
        msg = "Bad batch items type: expected {0}, received {1}"
        self.assertIsInstance(batch_items, list,
                              msg.format(list, type(batch_items)))
        self.assertEquals(1, len(batch_items),
                          self.msg.format('batch items', 'length',
                                          1, len(batch_items)))

        for batch_item in batch_items:
            msg = "Bad batch item type: expected {0}, received {1}"
            self.assertIsInstance(batch_item, messages.RequestBatchItem,
                                  msg.format(messages.RequestBatchItem,
                                             type(batch_item)))

            operation = batch_item.operation
            msg = "Bad operation type: expected {0}, received {1}"
            self.assertIsInstance(operation, contents.Operation,
                                  msg.format(contents.Operation,
                                             type(operation)))
            msg = "Bad operation value: expected {0}, received {1}"
            exp_value = enums.Operation.REGISTER
            rcv_value = operation.enum
            self.assertEqual(exp_value, rcv_value,
                             msg.format(exp_value, rcv_value))

            request_payload = batch_item.request_payload
            msg = "Bad request payload type: expected {0}, received {1}"
            exp_type = operations.RegisterRequestPayload
            rcv_type = type(request_payload)
            self.assertIsInstance(request_payload, exp_type,
                                  msg.format(exp_type, rcv_type))

            object_type = request_payload.object_type
            msg = "Bad object type type: expected {0}, received {1}"
            self.assertIsInstance(object_type, attr.ObjectType,
                                  msg.format(attr.ObjectType,
                                             type(object_type)))
            msg = "Bad object type value: expected {0}, received {1}"
            exp_value = enums.ObjectType.TEMPLATE
            rcv_value = object_type.enum
            self.assertEqual(exp_value, rcv_value,
                             msg.format(exp_value, rcv_value))

            template_attribute = request_payload.template_attribute
            msg = "Bad template attribute type: expected {0}, received {1}"
            exp_type = objects.TemplateAttribute
            rcv_type = type(template_attribute)
            self.assertIsInstance(template_attribute, exp_type,
                                  msg.format(exp_type, rcv_type))

            names = template_attribute.names
            exp_type = list
            rcv_type = type(names)
            msg = ErrorStrings.BAD_EXP_RECV.format('TemplateAttribute.names',
                                                   'type', '{0}', '{0}')
            self.assertIsInstance(names, exp_type,
                                  msg.format(exp_type, rcv_type))
            exp_length = 0
            rcv_length = len(names)
            msg = ErrorStrings.BAD_EXP_RECV.format('TemplateAttribute.names',
                                                   'length', '{0}', '{0}')
            self.assertEqual(exp_length, rcv_length,
                             msg.format(exp_length, rcv_length))

            attributes = template_attribute.attributes
            exp_type = list
            rcv_type = type(attributes)
            msg = ErrorStrings.BAD_EXP_RECV.format(
                'TemplateAttribute.attributes', 'type', '{0}', '{1}')
            self.assertIsInstance(names, exp_type,
                                  msg.format(exp_type, rcv_type))
            exp_length = 0
            rcv_length = len(attributes)
            msg = ErrorStrings.BAD_EXP_RECV.format(
                'TemplateAttribute.attributes', 'length', '{0}', '{1}')
            self.assertEqual(exp_length, rcv_length,
                             msg.format(exp_length, rcv_length))

    def test_register_request_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        batch_count = contents.BatchCount(1)
        req_header = messages.RequestHeader(protocol_version=prot_ver,
                                            batch_count=batch_count)

        operation = contents.Operation(enums.Operation.REGISTER)

        object_type = attr.ObjectType(enums.ObjectType.TEMPLATE)
        tmpl_attr = objects.TemplateAttribute()

        attributes = []

        name = objects.Attribute.AttributeName('Object Group')
        value = ObjectGroup('Group1')
        attribute = objects.Attribute(attribute_name=name,
                                      attribute_value=value)
        attributes.append(attribute)

        name = objects.Attribute.AttributeName('Application Specific '
                                               'Information')
        ap_n_name = 'ssl'
        ap_n_value = 'www.example.com'
        ap_n = ApplicationSpecificInformation.ApplicationNamespace(ap_n_name)
        ap_d = ApplicationSpecificInformation.ApplicationData(ap_n_value)
        value = ApplicationSpecificInformation(application_namespace=ap_n,
                                               application_data=ap_d)
        attribute = objects.Attribute(attribute_name=name,
                                      attribute_value=value)
        attributes.append(attribute)

        name = objects.Attribute.AttributeName('Contact Information')
        value = ContactInformation('Joe')
        attribute = objects.Attribute(attribute_name=name,
                                      attribute_value=value)
        attributes.append(attribute)

        name = objects.Attribute.AttributeName('x-Purpose')
        value = TextString('demonstration')
        attribute = objects.Attribute(attribute_name=name,
                                      attribute_value=value)
        attributes.append(attribute)

        name = objects.Attribute.AttributeName('Name')
        name_value = Name.NameValue('Template1')
        name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
        value = Name(name_value=name_value,
                     name_type=name_type)
        attribute = objects.Attribute(attribute_name=name,
                                      attribute_value=value)
        attributes.append(attribute)

        template = Template(attributes=attributes)

        request_payload = RegisterRequestPayload(object_type=object_type,
                                                 template_attribute=tmpl_attr,
                                                 secret=template)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=request_payload)
        request_message = messages.RequestMessage(request_header=req_header,
                                                  batch_items=[batch_item])
        request_message.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.register)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('request message', 'write',
                                         len_exp, len_rcv))

        msg = "Bad request message write: encoding mismatch"
        self.assertEqual(self.register, result, msg)


class TestResponseMessage(TestCase):

    def setUp(self):
        super(TestResponseMessage, self).setUp()
        self.stream = BytearrayStream()
        self.key_factory = KeyFactory()
        self.secret_factory = SecretFactory()
        self.msg = errors.ErrorStrings.BAD_EXP_RECV
        self.create = (
            '\x42\x00\x7B\x01\x00\x00\x00\xC0\x42\x00\x7A\x01\x00\x00\x00\x48'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x92\x09\x00\x00\x00\x08'
            '\x00\x00\x00\x00\x4F\x9A\x54\xE5\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\x68'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            '\x42\x00\x7F\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x42\x00\x7C\x01\x00\x00\x00\x40\x42\x00\x57\x05\x00\x00\x00\x04'
            '\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x94\x07\x00\x00\x00\x24'
            '\x66\x62\x34\x62\x35\x62\x39\x63\x2D\x36\x31\x38\x38\x2D\x34\x63'
            '\x36\x33\x2D\x38\x31\x34\x32\x2D\x66\x65\x39\x63\x33\x32\x38\x31'
            '\x32\x39\x66\x63\x00\x00\x00\x00')
        self.register = (
            '\x42\x00\x7B\x01\x00\x00\x00\xB0\x42\x00\x7A\x01\x00\x00\x00\x48'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x92\x09\x00\x00\x00\x08'
            '\x00\x00\x00\x00\x4F\x9A\x54\xE5\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\x58'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            '\x42\x00\x7F\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x42\x00\x7C\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            '\x35\x63\x39\x62\x38\x31\x65\x66\x2D\x34\x65\x65\x35\x2D\x34\x32'
            '\x63\x64\x2D\x62\x61\x32\x64\x2D\x63\x30\x30\x32\x66\x64\x64\x30'
            '\x63\x37\x62\x33\x00\x00\x00\x00')
        self.get = (
            '\x42\x00\x7B\x01\x00\x00\x01\x28\x42\x00\x7A\x01\x00\x00\x00\x48'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x92\x09\x00\x00\x00\x08'
            '\x00\x00\x00\x00\x4F\x9A\x54\xE7\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\xD0'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00'
            '\x42\x00\x7F\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x42\x00\x7C\x01\x00\x00\x00\xA8\x42\x00\x57\x05\x00\x00\x00\x04'
            '\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x94\x07\x00\x00\x00\x24'
            '\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            '\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            '\x33\x30\x33\x38\x00\x00\x00\x00\x42\x00\x8F\x01\x00\x00\x00\x60'
            '\x42\x00\x40\x01\x00\x00\x00\x58\x42\x00\x42\x05\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x45\x01\x00\x00\x00\x20'
            '\x42\x00\x43\x08\x00\x00\x00\x18\x73\x67\x57\x80\x51\x01\x2A\x6D'
            '\x13\x4A\x85\x5E\x25\xC8\xCD\x5E\x4C\xA1\x31\x45\x57\x29\xD3\xC8'
            '\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            '\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\xA8\x00\x00\x00\x00')
        self.destroy = (
            '\x42\x00\x7B\x01\x00\x00\x00\xB0\x42\x00\x7A\x01\x00\x00\x00\x48'
            '\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x92\x09\x00\x00\x00\x08'
            '\x00\x00\x00\x00\x4F\x9A\x54\xE5\x42\x00\x0D\x02\x00\x00\x00\x04'
            '\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x0F\x01\x00\x00\x00\x58'
            '\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x00'
            '\x42\x00\x7F\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            '\x42\x00\x7C\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            '\x66\x62\x34\x62\x35\x62\x39\x63\x2D\x36\x31\x38\x38\x2D\x34\x63'
            '\x36\x33\x2D\x38\x31\x34\x32\x2D\x66\x65\x39\x63\x33\x32\x38\x31'
            '\x32\x39\x66\x63\x00\x00\x00\x00')

    def tearDown(self):
        super(TestResponseMessage, self).tearDown()

    def test_create_response_read(self):
        self.stream = BytearrayStream(str(self.create))

        response_message = messages.ResponseMessage()
        response_message.read(self.stream)

        response_header = response_message.response_header
        self.assertIsInstance(response_header, messages.ResponseHeader,
                              self.msg.format('response header', 'type',
                                              messages.ResponseHeader,
                                              type(response_header)))
        protocol_version = response_header.protocol_version
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              self.msg.format('response header', 'value',
                                              contents.ProtocolVersion,
                                              type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              self.msg.format('protocol version major',
                                              'type', exp_type, rcv_type))
        self.assertEqual(1, protocol_version_major.value,
                         self.msg.format('protocol version major', 'value',
                                         1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor,
                              contents.ProtocolVersion.ProtocolVersionMinor,
                              self.msg.format('protocol version minor',
                                              'type', exp_type, rcv_type))
        self.assertEqual(1, protocol_version_minor.value,
                         self.msg.format('protocol version minor', 'value',
                                         1, protocol_version_minor.value))

        time_stamp = response_header.time_stamp
        value = 0x4f9a54e5  # Fri Apr 27 10:12:21 CEST 2012
        self.assertIsInstance(time_stamp, contents.TimeStamp,
                              self.msg.format('time stamp', 'value',
                                              contents.TimeStamp,
                                              type(time_stamp)))
        self.assertEqual(time_stamp.value, value,
                         self.msg.format('time stamp', 'value',
                                         time_stamp.value, value))

        batch_count = response_header.batch_count
        self.assertIsInstance(batch_count, contents.BatchCount,
                              self.msg.format('batch count', 'type',
                                              contents.BatchCount,
                                              type(batch_count)))
        self.assertEqual(1, batch_count.value,
                         self.msg.format('batch count', 'value', 1,
                                         batch_count.value))

        batch_items = response_message.batch_items
        self.assertIsInstance(batch_items, list,
                              self.msg.format('batch items', 'type',
                                              list, type(batch_items)))

        for batch_item in batch_items:
            self.assertIsInstance(batch_item, messages.ResponseBatchItem,
                                  self.msg.format('batch item', 'type',
                                                  messages.ResponseBatchItem,
                                                  type(batch_item)))

            operation = batch_item.operation
            self.assertIsInstance(operation, contents.Operation,
                                  self.msg.format('operation', 'type',
                                                  contents.Operation,
                                                  type(operation)))
            self.assertEqual(enums.Operation.CREATE, operation.enum,
                             self.msg.format('operation', 'value',
                                             enums.Operation.CREATE,
                                             operation.enum))

            result_status = batch_item.result_status
            self.assertIsInstance(result_status, contents.ResultStatus,
                                  self.msg.format('result status', 'type',
                                                  contents.ResultStatus,
                                                  type(result_status)))
            self.assertEqual(enums.ResultStatus.SUCCESS, result_status.enum,
                             self.msg.format('result status', 'value',
                                             enums.ResultStatus.SUCCESS,
                                             result_status.enum))

            response_payload = batch_item.response_payload
            exp_type = operations.CreateResponsePayload
            rcv_type = type(response_payload)
            self.assertIsInstance(response_payload, exp_type,
                                  self.msg.format('response payload', 'type',
                                                  exp_type, rcv_type))

            object_type = response_payload.object_type
            self.assertIsInstance(object_type, attr.ObjectType,
                                  self.msg.format('object type', 'type',
                                                  attr.ObjectType,
                                                  type(object_type)))
            self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, object_type.enum,
                             self.msg.format('object type', 'value',
                                             enums.ObjectType.SYMMETRIC_KEY,
                                             object_type.enum))

            unique_identifier = response_payload.unique_identifier
            value = 'fb4b5b9c-6188-4c63-8142-fe9c328129fc'
            self.assertIsInstance(unique_identifier, attr.UniqueIdentifier,
                                  self.msg.format('unique identifier', 'type',
                                                  attr.UniqueIdentifier,
                                                  type(unique_identifier)))
            self.assertEqual(value, unique_identifier.value,
                             self.msg.format('unique identifier', 'value',
                                             unique_identifier.value, value))

    def test_create_response_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        # Fri Apr 27 10:12:21 CEST 2012
        time_stamp = contents.TimeStamp(0x4f9a54e5)

        batch_count = contents.BatchCount(1)
        response_header = messages.ResponseHeader(protocol_version=prot_ver,
                                                  time_stamp=time_stamp,
                                                  batch_count=batch_count)
        operation = contents.Operation(enums.Operation.CREATE)
        result_status = contents.ResultStatus(enums.ResultStatus.SUCCESS)
        object_type = attr.ObjectType(enums.ObjectType.SYMMETRIC_KEY)

        uuid = 'fb4b5b9c-6188-4c63-8142-fe9c328129fc'
        uniq_id = attr.UniqueIdentifier(uuid)
        resp_pl = operations.CreateResponsePayload(object_type=object_type,
                                                   unique_identifier=uniq_id)
        batch_item = messages.ResponseBatchItem(operation=operation,
                                                result_status=result_status,
                                                response_payload=resp_pl)
        rm = messages.ResponseMessage(response_header=response_header,
                                      batch_items=[batch_item])
        rm.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.create)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('response message', 'write', len_exp,
                                         len_rcv))

        msg = "Bad response message write: encoding mismatch"
        self.assertEqual(self.create, result, msg)

    def test_get_response_read(self):
        self.stream = BytearrayStream(str(self.get))

        response_message = messages.ResponseMessage()
        response_message.read(self.stream)

        response_header = response_message.response_header
        self.assertIsInstance(response_header, messages.ResponseHeader,
                              self.msg.format('response header', 'type',
                                              messages.ResponseHeader,
                                              type(response_header)))
        protocol_version = response_header.protocol_version
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              self.msg.format('response header', 'value',
                                              contents.ProtocolVersion,
                                              type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              self.msg.format('protocol version major', 'type',
                                              exp_type, rcv_type))
        self.assertEqual(1, protocol_version_major.value,
                         self.msg.format('protocol version major', 'value',
                                         1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor, exp_type,
                              self.msg.format('protocol version minor', 'type',
                                              exp_type, rcv_type))
        self.assertEqual(1, protocol_version_minor.value,
                         self.msg.format('protocol version minor', 'value',
                                         1, protocol_version_minor.value))

        time_stamp = response_header.time_stamp
        value = 0x4f9a54e7  # Fri Apr 27 10:12:23 CEST 2012
        self.assertIsInstance(time_stamp, contents.TimeStamp,
                              self.msg.format('time stamp', 'value',
                                              contents.TimeStamp,
                                              type(time_stamp)))
        self.assertEqual(time_stamp.value, value,
                         self.msg.format('time stamp', 'value',
                                         time_stamp.value, value))

        batch_count = response_header.batch_count
        self.assertIsInstance(batch_count, contents.BatchCount,
                              self.msg.format('batch count', 'type',
                                              contents.BatchCount,
                                              type(batch_count)))
        self.assertEqual(1, batch_count.value,
                         self.msg.format('batch count', 'value', 1,
                                         batch_count.value))

        batch_items = response_message.batch_items
        self.assertIsInstance(batch_items, list,
                              self.msg.format('batch items', 'type',
                                              list, type(batch_items)))

        for batch_item in batch_items:
            self.assertIsInstance(batch_item, messages.ResponseBatchItem,
                                  self.msg.format('batch item', 'type',
                                                  messages.ResponseBatchItem,
                                                  type(batch_item)))

            operation = batch_item.operation
            self.assertIsInstance(operation, contents.Operation,
                                  self.msg.format('operation', 'type',
                                                  contents.Operation,
                                                  type(operation)))
            self.assertEqual(enums.Operation.GET, operation.enum,
                             self.msg.format('operation', 'value',
                                             enums.Operation.GET,
                                             operation.enum))

            result_status = batch_item.result_status
            self.assertIsInstance(result_status, contents.ResultStatus,
                                  self.msg.format('result status', 'type',
                                                  contents.ResultStatus,
                                                  type(result_status)))
            self.assertEqual(enums.ResultStatus.SUCCESS, result_status.enum,
                             self.msg.format('result status', 'value',
                                             enums.ResultStatus.SUCCESS,
                                             result_status.enum))

            response_payload = batch_item.response_payload
            exp_type = operations.GetResponsePayload
            rcv_type = type(response_payload)
            self.assertIsInstance(response_payload, exp_type,
                                  self.msg.format('response payload', 'type',
                                                  exp_type, rcv_type))

            object_type = response_payload.object_type
            self.assertIsInstance(object_type, attr.ObjectType,
                                  self.msg.format('object type', 'type',
                                                  attr.ObjectType,
                                                  type(object_type)))
            self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, object_type.enum,
                             self.msg.format('object type', 'value',
                                             enums.ObjectType.SYMMETRIC_KEY,
                                             object_type.enum))

            unique_identifier = response_payload.unique_identifier
            value = '49a1ca88-6bea-4fb2-b450-7e58802c3038'
            self.assertIsInstance(unique_identifier, attr.UniqueIdentifier,
                                  self.msg.format('unique identifier', 'type',
                                                  attr.UniqueIdentifier,
                                                  type(unique_identifier)))
            self.assertEqual(value, unique_identifier.value,
                             self.msg.format('unique identifier', 'value',
                                             unique_identifier.value, value))

            secret = response_payload.secret
            self.assertIsInstance(secret, SymmetricKey,
                                  self.msg.format('secret', 'type',
                                                  SymmetricKey, type(secret)))

            key_block = secret.key_block
            self.assertIsInstance(key_block, objects.KeyBlock,
                                  self.msg.format('key_block', 'type',
                                                  objects.KeyBlock,
                                                  type(key_block)))

            key_format_type = key_block.key_format_type
            exp_type = objects.KeyBlock.KeyFormatType
            rcv_type = type(key_format_type)
            self.assertIsInstance(key_format_type, exp_type,
                                  self.msg.format('key_format_type', 'type',
                                                  exp_type, rcv_type))

            key_value = key_block.key_value
            self.assertIsInstance(key_value, objects.KeyValue,
                                  self.msg.format('key_value', 'type',
                                                  objects.KeyValue,
                                                  type(key_value)))

            key_material = key_value.key_value.key_material
            value = bytearray('\x73\x67\x57\x80\x51\x01\x2A\x6D\x13\x4A\x85'
                              '\x5E\x25\xC8\xCD\x5E\x4C\xA1\x31\x45\x57\x29'
                              '\xD3\xC8')
            self.assertIsInstance(key_material, RawKey,
                                  self.msg.format('key_material', 'type',
                                                  RawKey,
                                                  type(key_material)))
            exp = utils.hexlify_bytearray(value)
            obs = utils.hexlify_bytearray(key_material.value)
            self.assertEqual(exp, obs, self.msg.format('key_material', 'value',
                                                       exp, obs))

            cryptographic_algorithm = key_block.cryptographic_algorithm
            exp_type = attr.CryptographicAlgorithm
            rcv_type = type(cryptographic_algorithm)
            self.assertIsInstance(cryptographic_algorithm, exp_type,
                                  self.msg.format('cryptographic_algorithm',
                                                  'type', exp_type, rcv_type))
            exp = enums.CryptographicAlgorithm.TRIPLE_DES
            obs = cryptographic_algorithm.enum
            self.assertEqual(exp, obs,
                             self.msg.format('cryptographic_algorithm',
                                             'value', exp, obs))

            cryptographic_length = key_block.cryptographic_length
            self.assertIsInstance(cryptographic_length,
                                  attr.CryptographicLength,
                                  self.msg.format('cryptographic_length',
                                                  'type',
                                                  attr.CryptographicLength,
                                                  type(cryptographic_length)))
            exp = 168
            obs = cryptographic_length.value
            self.assertEqual(exp, obs, self.msg.format('cryptographic_length',
                                                       'value', exp, obs))

    def test_get_response_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        # Fri Apr 27 10:12:23 CEST 2012
        time_stamp = contents.TimeStamp(0x4f9a54e7)

        batch_count = contents.BatchCount(1)
        response_header = messages.ResponseHeader(protocol_version=prot_ver,
                                                  time_stamp=time_stamp,
                                                  batch_count=batch_count)
        operation = contents.Operation(enums.Operation.GET)
        result_status = contents.ResultStatus(enums.ResultStatus.SUCCESS)
        object_type = attr.ObjectType(enums.ObjectType.SYMMETRIC_KEY)

        uuid = '49a1ca88-6bea-4fb2-b450-7e58802c3038'
        uniq_id = attr.UniqueIdentifier(uuid)

        key_type = enums.KeyFormatType.RAW
        key = bytearray('\x73\x67\x57\x80\x51\x01\x2A\x6D\x13\x4A\x85\x5E\x25'
                        '\xC8\xCD\x5E\x4C\xA1\x31\x45\x57\x29\xD3\xC8')

        crypto_algorithm = enums.CryptographicAlgorithm.TRIPLE_DES
        cryptographic_length = 168
        value = {'key_format_type': key_type,
                 'key_value': {'bytes': key},
                 'cryptographic_algorithm': crypto_algorithm,
                 'cryptographic_length': cryptographic_length}
        secret = self.secret_factory.create_secret(ObjectType.SYMMETRIC_KEY,
                                                   value)
        resp_pl = operations.GetResponsePayload(object_type=object_type,
                                                unique_identifier=uniq_id,
                                                secret=secret)
        batch_item = messages.ResponseBatchItem(operation=operation,
                                                result_status=result_status,
                                                response_payload=resp_pl)
        rm = messages.ResponseMessage(response_header=response_header,
                                      batch_items=[batch_item])
        rm.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.get)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('get response message', 'write',
                                         len_exp, len_rcv))

        msg = "Bad get response message write: encoding mismatch"
        print self.get
        print result
        self.assertEqual(self.get, result, msg)

    def test_destroy_response_read(self):
        self.stream = BytearrayStream(self.destroy)

        response_message = messages.ResponseMessage()
        response_message.read(self.stream)

        response_header = response_message.response_header
        msg = "Bad response header type: expected {0}, received{1}"
        self.assertIsInstance(response_header, messages.ResponseHeader,
                              msg.format(messages.ResponseHeader,
                                         type(response_header)))

        protocol_version = response_header.protocol_version
        msg = "Bad protocol version type: expected {0}, received {1}"
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              msg.format(contents.ProtocolVersion,
                                         type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        msg = "Bad protocol version major type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version major value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_major.value,
                         msg.format(1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        msg = "Bad protocol version minor type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version minor value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_minor.value,
                         msg.format(1, protocol_version_minor.value))

        time_stamp = response_header.time_stamp
        value = 0x4f9a54e5  # Fri Apr 27 10:12:21 CEST 2012
        self.assertIsInstance(time_stamp, contents.TimeStamp,
                              self.msg.format('time stamp', 'value',
                                              contents.TimeStamp,
                                              type(time_stamp)))
        self.assertEqual(time_stamp.value, value,
                         self.msg.format('time stamp', 'value',
                                         time_stamp.value, value))

        batch_count = response_header.batch_count
        msg = "Bad batch count type: expected {0}, received {1}"
        self.assertIsInstance(batch_count, contents.BatchCount,
                              msg.format(contents.BatchCount,
                                         type(batch_count)))
        msg = "Bad batch count value: expected {0}, received {1}"
        self.assertEqual(1, batch_count.value,
                         msg.format(1, batch_count.value))

        batch_items = response_message.batch_items
        msg = "Bad batch items type: expected {0}, received {1}"
        self.assertIsInstance(batch_items, list,
                              msg.format(list, type(batch_items)))
        self.assertEquals(1, len(batch_items),
                          self.msg.format('batch items', 'length',
                                          1, len(batch_items)))

        for batch_item in batch_items:
            msg = "Bad batch item type: expected {0}, received {1}"
            self.assertIsInstance(batch_item, messages.ResponseBatchItem,
                                  msg.format(messages.ResponseBatchItem,
                                             type(batch_item)))

            operation = batch_item.operation
            msg = "Bad operation type: expected {0}, received {1}"
            self.assertIsInstance(operation, contents.Operation,
                                  msg.format(contents.Operation,
                                             type(operation)))
            msg = "Bad operation value: expected {0}, received {1}"
            exp_value = enums.Operation.DESTROY
            rcv_value = operation.enum
            self.assertEqual(exp_value, rcv_value,
                             msg.format(exp_value, rcv_value))

            result_status = batch_item.result_status
            self.assertIsInstance(result_status, contents.ResultStatus,
                                  self.msg.format('result status', 'type',
                                                  contents.ResultStatus,
                                                  type(result_status)))
            self.assertEqual(enums.ResultStatus.SUCCESS, result_status.enum,
                             self.msg.format('result status', 'value',
                                             enums.ResultStatus.SUCCESS,
                                             result_status.enum))

            response_payload = batch_item.response_payload
            msg = "Bad response payload type: expected {0}, received {1}"
            exp_type = operations.DestroyResponsePayload
            rcv_type = type(response_payload)
            self.assertIsInstance(response_payload, exp_type,
                                  msg.format(exp_type, rcv_type))

            unique_identifier = response_payload.unique_identifier
            msg = "Bad unique identifier type: expected {0}, received {1}"
            self.assertIsInstance(unique_identifier, attr.UniqueIdentifier,
                                  msg.format(attr.UniqueIdentifier,
                                             type(unique_identifier)))
            msg = "Bad unique identifier value: expected {0}, received {1}"
            exp_value = 'fb4b5b9c-6188-4c63-8142-fe9c328129fc'
            rcv_value = unique_identifier.value
            self.assertEqual(exp_value, rcv_value,
                             msg.format(exp_value, rcv_value))

    def test_destroy_response_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        # Fri Apr 27 10:12:21 CEST 2012
        time_stamp = contents.TimeStamp(0x4f9a54e5)

        batch_count = contents.BatchCount(1)
        resp_hdr = messages.ResponseHeader(protocol_version=prot_ver,
                                           time_stamp=time_stamp,
                                           batch_count=batch_count)

        operation = contents.Operation(enums.Operation.DESTROY)
        result_status = contents.ResultStatus(enums.ResultStatus.SUCCESS)

        uuid = attr.UniqueIdentifier('fb4b5b9c-6188-4c63-8142-fe9c328129fc')
        resp_pl = DestroyResponsePayload(unique_identifier=uuid)
        batch_item = messages.ResponseBatchItem(operation=operation,
                                                result_status=result_status,
                                                response_payload=resp_pl)
        response_message = messages.ResponseMessage(response_header=resp_hdr,
                                                    batch_items=[batch_item])
        response_message.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.destroy)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('response message', 'write',
                                         len_exp, len_rcv))

        msg = "Bad response message write: encoding mismatch"
        self.assertEqual(self.destroy, result, msg)

    def test_register_response_read(self):
        self.stream = BytearrayStream(self.register)

        response_message = messages.ResponseMessage()
        response_message.read(self.stream)

        response_header = response_message.response_header
        msg = "Bad response header type: expected {0}, received{1}"
        self.assertIsInstance(response_header, messages.ResponseHeader,
                              msg.format(messages.ResponseHeader,
                                         type(response_header)))

        protocol_version = response_header.protocol_version
        msg = "Bad protocol version type: expected {0}, received {1}"
        self.assertIsInstance(protocol_version, contents.ProtocolVersion,
                              msg.format(contents.ProtocolVersion,
                                         type(protocol_version)))

        protocol_version_major = protocol_version.protocol_version_major
        msg = "Bad protocol version major type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMajor
        rcv_type = type(protocol_version_major)
        self.assertIsInstance(protocol_version_major, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version major value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_major.value,
                         msg.format(1, protocol_version_major.value))

        protocol_version_minor = protocol_version.protocol_version_minor
        msg = "Bad protocol version minor type: expected {0}, received {1}"
        exp_type = contents.ProtocolVersion.ProtocolVersionMinor
        rcv_type = type(protocol_version_minor)
        self.assertIsInstance(protocol_version_minor, exp_type,
                              msg.format(exp_type, rcv_type))
        msg = "Bad protocol version minor value: expected {0}, received {1}"
        self.assertEqual(1, protocol_version_minor.value,
                         msg.format(1, protocol_version_minor.value))

        time_stamp = response_header.time_stamp
        value = 0x4f9a54e5  # Fri Apr 27 10:12:21 CEST 2012
        self.assertIsInstance(time_stamp, contents.TimeStamp,
                              self.msg.format('time stamp', 'value',
                                              contents.TimeStamp,
                                              type(time_stamp)))
        self.assertEqual(time_stamp.value, value,
                         self.msg.format('time stamp', 'value',
                                         time_stamp.value, value))

        batch_count = response_header.batch_count
        msg = "Bad batch count type: expected {0}, received {1}"
        self.assertIsInstance(batch_count, contents.BatchCount,
                              msg.format(contents.BatchCount,
                                         type(batch_count)))
        msg = "Bad batch count value: expected {0}, received {1}"
        self.assertEqual(1, batch_count.value,
                         msg.format(1, batch_count.value))

        batch_items = response_message.batch_items
        msg = "Bad batch items type: expected {0}, received {1}"
        self.assertIsInstance(batch_items, list,
                              msg.format(list, type(batch_items)))
        self.assertEquals(1, len(batch_items),
                          self.msg.format('batch items', 'length',
                                          1, len(batch_items)))

        for batch_item in batch_items:
            msg = "Bad batch item type: expected {0}, received {1}"
            self.assertIsInstance(batch_item, messages.ResponseBatchItem,
                                  msg.format(messages.ResponseBatchItem,
                                             type(batch_item)))

            operation = batch_item.operation
            msg = "Bad operation type: expected {0}, received {1}"
            self.assertIsInstance(operation, contents.Operation,
                                  msg.format(contents.Operation,
                                             type(operation)))
            msg = "Bad operation value: expected {0}, received {1}"
            exp_value = enums.Operation.REGISTER
            rcv_value = operation.enum
            self.assertEqual(exp_value, rcv_value,
                             msg.format(exp_value, rcv_value))

            result_status = batch_item.result_status
            self.assertIsInstance(result_status, contents.ResultStatus,
                                  self.msg.format('result status', 'type',
                                                  contents.ResultStatus,
                                                  type(result_status)))
            self.assertEqual(enums.ResultStatus.SUCCESS, result_status.enum,
                             self.msg.format('result status', 'value',
                                             enums.ResultStatus.SUCCESS,
                                             result_status.enum))

            response_payload = batch_item.response_payload
            msg = "Bad response payload type: expected {0}, received {1}"
            exp_type = operations.RegisterResponsePayload
            rcv_type = type(response_payload)
            self.assertIsInstance(response_payload, exp_type,
                                  msg.format(exp_type, rcv_type))

            unique_identifier = response_payload.unique_identifier
            msg = "Bad unique identifier type: expected {0}, received {1}"
            self.assertIsInstance(unique_identifier, attr.UniqueIdentifier,
                                  msg.format(attr.UniqueIdentifier,
                                             type(unique_identifier)))
            msg = "Bad unique identifier value: expected {0}, received {1}"
            exp_value = '5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3'
            rcv_value = unique_identifier.value
            self.assertEqual(exp_value, rcv_value,
                             msg.format(exp_value, rcv_value))

    def test_register_response_write(self):
        prot_ver = contents.ProtocolVersion.create(1, 1)

        # Fri Apr 27 10:12:21 CEST 2012
        time_stamp = contents.TimeStamp(0x4f9a54e5)

        batch_count = contents.BatchCount(1)
        resp_hdr = messages.ResponseHeader(protocol_version=prot_ver,
                                           time_stamp=time_stamp,
                                           batch_count=batch_count)

        operation = contents.Operation(enums.Operation.REGISTER)
        result_status = contents.ResultStatus(enums.ResultStatus.SUCCESS)

        uuid = attr.UniqueIdentifier('5c9b81ef-4ee5-42cd-ba2d-c002fdd0c7b3')
        resp_pl = RegisterResponsePayload(unique_identifier=uuid)
        batch_item = messages.ResponseBatchItem(operation=operation,
                                                result_status=result_status,
                                                response_payload=resp_pl)
        response_message = messages.ResponseMessage(response_header=resp_hdr,
                                                    batch_items=[batch_item])
        response_message.write(self.stream)

        result = self.stream.read()
        len_exp = len(self.register)
        len_rcv = len(result)
        self.assertEqual(len_exp, len_rcv,
                         self.msg.format('response message', 'write',
                                         len_exp, len_rcv))

        msg = "Bad response message write: encoding mismatch"
        self.assertEqual(self.register, result, msg)
