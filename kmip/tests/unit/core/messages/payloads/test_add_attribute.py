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

import binascii

from testtools import TestCase

from kmip.core import objects
from kmip.core import utils
from kmip.core import exceptions

from kmip.core.attributes import Name
from kmip.core.attributes import ContactInformation

from kmip.core.factories.attributes import AttributeFactory

from kmip.core.enums import AttributeType
from kmip.core.enums import NameType

from kmip.core.messages.payloads import add_attribute


class TestAddAttributePayload(TestCase):

    def setUp(self):
        super(TestAddAttributePayload, self).setUp()

        self.attr_factory = AttributeFactory()
        self.name_uid = 'b4faee10-aa2a-4446-8ad4-0881f3422959'
        self.ci_uid = '3'
        self.ci_label = AttributeType.CONTACT_INFORMATION.value
        self.ci_value = 'https://github.com/OpenKMIP/PyKMIP'
        self.ci_uid_bis = '4'
        self.ci_value_bis = 'https://github.com/OpenSC/OpenSC'

        attr_name = Name.create(
            Name.NameValue(value='TESTNAME'),
            Name.NameType(value=NameType.UNINTERPRETED_TEXT_STRING))
        self.attr_name = self.attr_factory.create_attribute(
            AttributeType.NAME,
            attr_name)

        self.attr_contact_information = self.attr_factory.create_attribute(
            AttributeType.CONTACT_INFORMATION,
            self.ci_value)
        self.attr_contact_information_bis = self.attr_factory.create_attribute(
            AttributeType.CONTACT_INFORMATION,
            self.ci_value_bis)

        self.uid_invalid = 1234
        self.attr_invalid = "invalid"

        '''
        <RequestPayload>
          <UniqueIdentifier type="TextString" value="3"/>
          <Attribute>
            <AttributeName type="TextString" value="Contact Information"/>
            <AttributeValue type="TextString" value="https://github.com/Ope...
          </Attribute>
        </RequestPayload>
        '''
        self.blob_request = binascii.unhexlify(
            '4200790100000068420094070000000133000000000000004200080100000050'
            '42000a0700000013436f6e7461637420496e666f726d6174696f6e0000000000'
            '42000b070000002268747470733a2f2f6769746875622e636f6d2f4f70656e4b'
            '4d49502f50794b4d4950000000000000'
        )

        '''
        <ResponsePayload>
          <UniqueIdentifier type="TextString" value="3"/>
          <Attribute>
            <AttributeName type="TextString" value="Contact Information"/>
            <AttributeValue type="TextString" value="https://github.com/Ope...
          </Attribute>
        </ResponsePayload>
        '''
        self.blob_response = binascii.unhexlify(
            '42007c0100000068420094070000000133000000000000004200080100000050'
            '42000a0700000013436f6e7461637420496e666f726d6174696f6e0000000000'
            '42000b070000002268747470733a2f2f6769746875622e636f6d2f4f70656e4b'
            '4d49502f50794b4d4950000000000000'
        )

        '''
        Response payload without 'Vendor Identification' instead of 'UID'
        '''
        self.blob_invalid_response = binascii.unhexlify(
            '42007c010000006842009C070000000133000000000000004200080100000050'
            '42000a0700000013436f6e7461637420496e666f726d6174696f6e0000000000'
            '42000b070000002268747470733a2f2f6769746875622e636f6d2f4f70656e4b'
            '4d49502f50794b4d4950000000000000'
        )


class TestAddAttributeRequestPayload(TestAddAttributePayload):

    def setUp(self):
        super(TestAddAttributeRequestPayload, self).setUp()

    def tearDown(self):
        super(TestAddAttributeRequestPayload, self).tearDown()

    def test_init_with_none(self):
        add_attribute.AddAttributeRequestPayload()

    def test_init_with_args(self):
        add_attribute.AddAttributeRequestPayload(
            self.name_uid,
            self.attr_name)
        add_attribute.AddAttributeRequestPayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)

    def test_validate_with_invalid_uid(self):
        args = [self.uid_invalid, self.attr_name]
        self.assertRaises(
            TypeError,
            add_attribute.AddAttributeRequestPayload,
            *args)

    def test_validate_with_invalid_attribute(self):
        args = [self.name_uid, self.attr_invalid]
        error_msg = ("attribute must be a Attribute object, "
                     "observed: {0}").format(
                        type(self.attr_invalid))
        self.assertRaisesRegexp(
            TypeError,
            error_msg,
            add_attribute.AddAttributeRequestPayload,
            *args)

    def test_read(self):
        stream = utils.BytearrayStream((self.blob_request))

        payload = add_attribute.AddAttributeRequestPayload()
        payload.read(stream)
        self.assertIsInstance(payload.attribute, objects.Attribute)
        self.assertEqual(
            payload.attribute.attribute_name.value,
            "Contact Information")
        self.assertIsInstance(
            payload.attribute.attribute_value,
            ContactInformation)
        self.assertEqual(
            payload.attribute.attribute_value.value,
            self.ci_value)

    def test_write(self):
        stream = utils.BytearrayStream()
        expected = self.blob_request

        payload = add_attribute.AddAttributeRequestPayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)

        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)
        print("length_expected {0}; length_received {1}".format(
            length_expected, length_received))

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)
        self.assertEqual(expected, stream.buffer, msg)

    def test_repr_str(self):
        payload = add_attribute.AddAttributeRequestPayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)

        expected = "AddAttributeRequestPayload(uid={0}".format(self.ci_uid)
        expected += ", attribute=('{0}':'{1}'))".format(
            self.ci_label, self.ci_value)

        self.assertEqual(expected, repr(payload))
        self.assertEqual(expected, str(payload))

    def test__eq(self):
        payload = add_attribute.AddAttributeRequestPayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)
        payload_same = add_attribute.AddAttributeRequestPayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)
        payload_other_uid = add_attribute.AddAttributeRequestPayload(
            uid=self.ci_uid_bis,
            attribute=self.attr_contact_information)
        payload_other_value = add_attribute.AddAttributeRequestPayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information_bis)

        self.assertTrue(payload == payload_same)
        self.assertTrue(payload != payload_other_value)
        self.assertTrue(payload != payload_other_uid)
        self.assertTrue(payload != 'invalid')
        self.assertFalse(payload != payload_same)
        self.assertFalse(payload == payload_other_value)
        self.assertFalse(payload == payload_other_uid)
        self.assertFalse(payload == 'invalid')


class TestAddAttributeResponsePayload(TestAddAttributePayload):

    def setUp(self):
        super(TestAddAttributeResponsePayload, self).setUp()

    def tearDown(self):
        super(TestAddAttributeResponsePayload, self).tearDown()

    def test_init_with_none(self):
        add_attribute.AddAttributeResponsePayload()

    def test_init_with_args(self):
        add_attribute.AddAttributeResponsePayload(
            self.name_uid,
            self.attr_name)
        add_attribute.AddAttributeResponsePayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)

    def test_validate_with_invalid_uid(self):
        args = [self.uid_invalid, self.attr_name]
        self.assertRaises(
            TypeError,
            add_attribute.AddAttributeResponsePayload,
            *args)

    def test_validate_with_invalid_attribute(self):
        args = [self.name_uid, self.attr_invalid]
        error_msg = ("attribute must be a Attribute object, "
                     "observed: {0}").format(type(self.attr_invalid))
        self.assertRaisesRegexp(
            TypeError,
            error_msg,
            add_attribute.AddAttributeResponsePayload,
            *args)

    def test_read(self):
        stream = utils.BytearrayStream((self.blob_response))

        payload = add_attribute.AddAttributeResponsePayload()
        payload.read(stream)
        self.assertIsInstance(payload.attribute, objects.Attribute)
        self.assertEqual(
            payload.attribute.attribute_name.value,
            "Contact Information")
        self.assertIsInstance(
            payload.attribute.attribute_value,
            ContactInformation)
        self.assertEqual(
            payload.attribute.attribute_value.value,
            self.ci_value)

    def test_read_invalid_response(self):
        stream = utils.BytearrayStream((self.blob_invalid_response))
        payload = add_attribute.AddAttributeResponsePayload()

        args = [stream]
        self.assertRaises(exceptions.InvalidKmipEncoding, payload.read, *args)

    def test_write(self):
        stream = utils.BytearrayStream()
        expected = self.blob_response

        payload = add_attribute.AddAttributeResponsePayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)

        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)
        print("length_expected {0}; length_received {1}".format(
            length_expected, length_received))

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)
        self.assertEqual(expected, stream.buffer, msg)

    def test_repr_str(self):
        payload = add_attribute.AddAttributeResponsePayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)

        expected = "AddAttributeResponsePayload(uid={0}".format(self.ci_uid)
        expected += ", attribute=('{0}':'{1}'))".format(
            self.ci_label, self.ci_value)

        self.assertEqual(expected, repr(payload))
        self.assertEqual(expected, str(payload))

    def test__eq(self):
        payload = add_attribute.AddAttributeResponsePayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)
        payload_same = add_attribute.AddAttributeResponsePayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information)
        payload_other_uid = add_attribute.AddAttributeResponsePayload(
            uid=self.ci_uid_bis,
            attribute=self.attr_contact_information)
        payload_other_value = add_attribute.AddAttributeResponsePayload(
            uid=self.ci_uid,
            attribute=self.attr_contact_information_bis)

        self.assertTrue(payload == payload_same)
        self.assertTrue(payload != payload_other_value)
        self.assertTrue(payload != payload_other_uid)
        self.assertTrue(payload != 'invalid')
        self.assertFalse(payload != payload_same)
        self.assertFalse(payload == payload_other_value)
        self.assertFalse(payload == payload_other_uid)
        self.assertFalse(payload == 'invalid')
