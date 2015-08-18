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

import copy
import testtools

from kmip.core import exceptions
from kmip.core import utils

from kmip.core.messages.payloads import get_attribute_list


class TestGetAttributeListRequestPayload(testtools.TestCase):
    """
    Test suite for the GetAttributeList request payload.
    """

    def setUp(self):
        super(TestGetAttributeListRequestPayload, self).setUp()

        # Encodings taken from Sections 3.1.4 of the KMIP 1.1 testing
        # documentation.
        self.encoding_with_uid = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'))

        self.encoding_without_uid = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x00'))

        self.uid = 'b4faee10-aa2a-4446-8ad4-0881f3422959'

    def tearDown(self):
        super(TestGetAttributeListRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a GetAttributeList request payload can be constructed with
        no arguments.
        """
        get_attribute_list.GetAttributeListRequestPayload()

    def test_init_with_args(self):
        """
        Test that a GetAttributeList request payload can be constructed with a
        valid value.
        """
        get_attribute_list.GetAttributeListRequestPayload(self.uid)

    def test_validate_with_invalid_uid(self):
        """
        Test that a TypeError exception is raised when an invalid ID is used
        to construct a GetAttributeList request payload.
        """
        kwargs = {'uid': 0}
        self.assertRaisesRegexp(
            TypeError, "uid must be a string",
            get_attribute_list.GetAttributeListRequestPayload, **kwargs)

    def test_read(self):
        """
        Test that a GetAttributeList request payload can be read from a data
        stream.
        """
        payload = get_attribute_list.GetAttributeListRequestPayload()
        payload.read(self.encoding_with_uid)
        self.assertEqual(self.uid, payload.uid)

    def test_read_with_no_uid(self):
        """
        Test that a GetAttributeList request payload with no ID can be read
        from a data stream.
        """
        payload = get_attribute_list.GetAttributeListRequestPayload()
        payload.read(self.encoding_without_uid)
        self.assertEqual(None, payload.uid)

    def test_write(self):
        """
        Test that a GetAttributeList request payload can be written to a data
        stream.
        """
        payload = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.encoding_with_uid), len(stream))
        self.assertEqual(self.encoding_with_uid, stream)

    def test_write_with_no_uid(self):
        """
        Test that a GetAttributeList request payload with no ID can be written
        to a data stream.
        """
        payload = get_attribute_list.GetAttributeListRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.encoding_without_uid), len(stream))
        self.assertEqual(self.encoding_without_uid, stream)

    def test_repr(self):
        """
        Test that repr can be applied to a GetAttributeList request payload.
        """
        payload = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        args = "uid={0}".format(payload.uid)
        expected = "GetAttributeListRequestPayload({0})".format(args)
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetAttributeList request payload.
        """
        payload = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        expected = str({'uid': payload.uid})
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributeList request payloads with the same data.
        """
        a = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        b = get_attribute_list.GetAttributeListRequestPayload(self.uid)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_uid(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributeList request payloads with different data.
        """
        a = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        b = get_attribute_list.GetAttributeListRequestPayload('invalid')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        GetAttributeList request payload to a non-GetAttributeList request
        payload.
        """
        a = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two GetAttributeList request payloads with the same internal data.
        """
        a = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        b = get_attribute_list.GetAttributeListRequestPayload(self.uid)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_uid(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributeList request payloads with different data.
        """
        a = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        b = get_attribute_list.GetAttributeListRequestPayload('invalid')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        GetAttributeList request payload to a non-GetAttributeList request
        payload.
        """
        a = get_attribute_list.GetAttributeListRequestPayload(self.uid)
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)


class TestGetAttributeListResponsePayload(testtools.TestCase):
    """
    Test encodings obtained from Sections 12.1 and 12.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestGetAttributeListResponsePayload, self).setUp()

        # Encodings taken from Sections 3.1.4 of the KMIP 1.1 testing
        # documentation.
        self.encoding_with_uid_with_names = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x01\x60\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x06'
            b'\x44\x69\x67\x65\x73\x74\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x0A'
            b'\x4C\x65\x61\x73\x65\x20\x54\x69\x6D\x65\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C\x49\x6E\x69\x74\x69\x61\x6C\x20'
            b'\x44\x61\x74\x65\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x55\x6E\x69\x71\x75\x65\x20\x49\x64\x65\x6E\x74\x69\x66\x69\x65'
            b'\x72\x00\x00\x00\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B\x42\x00\x0A\x07\x00\x00\x00\x0B'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x54\x79\x70\x65\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x13\x43\x6F\x6E\x74\x61\x63\x74\x20'
            b'\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x10\x4C\x61\x73\x74\x20\x43\x68\x61'
            b'\x6E\x67\x65\x20\x44\x61\x74\x65'))
        self.encoding_without_uid_with_names = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x01\x60\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00\x42\x00\x0A\x07\x00\x00\x00\x05'
            b'\x53\x74\x61\x74\x65\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x06'
            b'\x44\x69\x67\x65\x73\x74\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x0A'
            b'\x4C\x65\x61\x73\x65\x20\x54\x69\x6D\x65\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C\x49\x6E\x69\x74\x69\x61\x6C\x20'
            b'\x44\x61\x74\x65\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x55\x6E\x69\x71\x75\x65\x20\x49\x64\x65\x6E\x74\x69\x66\x69\x65'
            b'\x72\x00\x00\x00\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x04'
            b'\x4E\x61\x6D\x65\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x18'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x55\x73'
            b'\x61\x67\x65\x20\x4D\x61\x73\x6B\x42\x00\x0A\x07\x00\x00\x00\x0B'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x54\x79\x70\x65\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x13\x43\x6F\x6E\x74\x61\x63\x74\x20'
            b'\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x00\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x10\x4C\x61\x73\x74\x20\x43\x68\x61'
            b'\x6E\x67\x65\x20\x44\x61\x74\x65'))
        self.encoding_with_uid_without_names = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x62\x34\x66\x61\x65\x65\x31\x30\x2D\x61\x61\x32\x61\x2D\x34\x34'
            b'\x34\x36\x2D\x38\x61\x64\x34\x2D\x30\x38\x38\x31\x66\x33\x34\x32'
            b'\x32\x39\x35\x39\x00\x00\x00\x00'))

        self.uid = 'b4faee10-aa2a-4446-8ad4-0881f3422959'
        self.attribute_names = list((
            'Cryptographic Length',
            'Cryptographic Algorithm',
            'State',
            'Digest',
            'Lease Time',
            'Initial Date',
            'Unique Identifier',
            'Name',
            'Cryptographic Usage Mask',
            'Object Type',
            'Contact Information',
            'Last Change Date'))

    def tearDown(self):
        super(TestGetAttributeListResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a GetAttributeList response payload can be constructed.
        """
        get_attribute_list.GetAttributeListResponsePayload()

    def test_init_with_args(self):
        """
        Test that a GetAttributeList response payload can be constructed with
        valid values.
        """
        get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)

    def test_validate_with_invalid_uid(self):
        """
        Test that a TypeError exception is raised when an invalid ID is used
        to construct a GetAttributeList response payload.
        """
        kwargs = {'uid': 0, 'attribute_names': self.attribute_names}
        self.assertRaisesRegexp(
            TypeError, "uid must be a string",
            get_attribute_list.GetAttributeListResponsePayload, **kwargs)

    def test_validate_with_invalid_attribute_names(self):
        """
        Test that a TypeError exception is raised when an invalid attribute
        name list is used to construct a GetAttributeList response payload.
        """
        kwargs = {'uid': self.uid, 'attribute_names': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "attribute names must be a list",
            get_attribute_list.GetAttributeListResponsePayload, **kwargs)

    def test_validate_with_invalid_attribute_name(self):
        """
        Test that a TypeError exception is raised when an invalid attribute
        name is used to construct a GetAttributeList response payload object.
        """
        kwargs = {'uid': self.uid, 'attribute_names': [0]}
        self.assertRaises(
            TypeError, get_attribute_list.GetAttributeListResponsePayload,
            **kwargs)

        kwargs = {'uid': self.uid, 'attribute_names': ['', 0, '']}
        self.assertRaises(
            TypeError, get_attribute_list.GetAttributeListResponsePayload,
            **kwargs)

    def test_read(self):
        """
        Test that a GetAttributeList response payload can be read from a data
        stream.
        """
        payload = get_attribute_list.GetAttributeListResponsePayload()
        payload.read(self.encoding_with_uid_with_names)

        self.assertEqual(self.uid, payload.uid)
        self.assertEqual(self.attribute_names, payload.attribute_names)

    def test_read_with_no_uid(self):
        """
        Test that an InvalidKmipEncoding error gets raised when attempting to
        read a GetAttributeList response encoding with no ID data.
        """
        payload = get_attribute_list.GetAttributeListResponsePayload()
        self.assertRaisesRegexp(
            exceptions.InvalidKmipEncoding, "expected uid encoding not found",
            payload.read, self.encoding_without_uid_with_names)

    def test_read_with_no_attribute_names(self):
        """
        Test that a GetAttributeList response payload without attribute name
        data can be read from a data stream.
        """
        payload = get_attribute_list.GetAttributeListResponsePayload()
        payload.read(self.encoding_with_uid_without_names)

        self.assertEqual(self.uid, payload.uid)
        self.assertEqual(list(), payload.attribute_names)

    def test_write(self):
        """
        Test that a GetAttributeList response payload can be written to a data
        stream.
        """
        payload = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.encoding_with_uid_with_names), len(stream))
        self.assertEqual(self.encoding_with_uid_with_names, stream)

    def test_write_with_no_attribute_names(self):
        """
        Test that a GetAttributeList response payload with no attribute name
        data can be written to a data stream.
        """
        payload = get_attribute_list.GetAttributeListResponsePayload(self.uid)
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.encoding_with_uid_without_names), len(stream))
        self.assertEqual(self.encoding_with_uid_without_names, stream)

    def test_repr(self):
        """
        Test that repr can be applied to a GetAttributeList response payload.
        """
        payload = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        args = "uid={0}, attribute_names={1}".format(
            payload.uid, payload.attribute_names)
        expected = "GetAttributeListResponsePayload({0})".format(args)
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetAttributeList response payload.
        """
        payload = get_attribute_list.GetAttributeListResponsePayload(self.uid)
        expected = str({'uid': payload.uid,
                        'attribute_names': payload.attribute_names})
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributeList response payloads with the same data.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_uid(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributeList response payloads with different data.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            'invalid', self.attribute_names)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attribute_names(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributeList response payloads with different data.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, list())

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attribute_name(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributeList response payloads with different data.
        """
        alt_names = copy.deepcopy(self.attribute_names)
        alt_names[0] = 'invalid'
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, alt_names)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        GetAttributeList response payload to a non-GetAttributeList response
        payload.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two GetAttributeList response payloads with the same internal data.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_uid(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributeList request payloads with different data.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            'invalid', self.attribute_names)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attribute_names(self):
        """
        Test that the inequality operator returns False when comparing two
        GetAttributeList response payloads with different data.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, list())

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attribute_name(self):
        """
        Test that the inequality operator returns False when comparing two
        GetAttributeList response payloads with different data.
        """
        alt_names = copy.deepcopy(self.attribute_names)
        alt_names[0] = 'Operation Policy Name'
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, alt_names)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        GetAttributeList response payload to a non-GetAttributeList response
        payload.
        """
        a = get_attribute_list.GetAttributeListResponsePayload(
            self.uid, self.attribute_names)
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)
