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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads


class TestGetAttributesRequestPayload(testtools.TestCase):
    """
    Test suite for the GetAttributes request payload.
    """

    def setUp(self):
        super(TestGetAttributesRequestPayload, self).setUp()

        # Encodings taken from Sections 3.1.2 of the KMIP 1.1 testing
        # documentation.
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xA8\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x37\x30\x33\x32\x35\x30\x62\x2D\x34\x64\x34\x30\x2D\x34\x64'
            b'\x65\x32\x2D\x39\x33\x61\x30\x2D\x63\x34\x39\x34\x61\x31\x64\x34'
            b'\x61\x65\x34\x30\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x20\x41\x70\x70\x6C\x69\x63\x61\x74'
            b'\x69\x6F\x6E\x20\x53\x70\x65\x63\x69\x66\x69\x63\x20\x49\x6E\x66'
            b'\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x42\x00\x0A\x07\x00\x00\x00\x13'
            b'\x43\x6F\x6E\x74\x61\x63\x74\x20\x49\x6E\x66\x6F\x72\x6D\x61\x74'
            b'\x69\x6F\x6E\x00\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x09'
            b'\x78\x2D\x50\x75\x72\x70\x6F\x73\x65\x00\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_sans_unique_identifier = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x78\x42\x00\x0A\x07\x00\x00\x00\x0C'
            b'\x4F\x62\x6A\x65\x63\x74\x20\x47\x72\x6F\x75\x70\x00\x00\x00\x00'
            b'\x42\x00\x0A\x07\x00\x00\x00\x20\x41\x70\x70\x6C\x69\x63\x61\x74'
            b'\x69\x6F\x6E\x20\x53\x70\x65\x63\x69\x66\x69\x63\x20\x49\x6E\x66'
            b'\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x42\x00\x0A\x07\x00\x00\x00\x13'
            b'\x43\x6F\x6E\x74\x61\x63\x74\x20\x49\x6E\x66\x6F\x72\x6D\x61\x74'
            b'\x69\x6F\x6E\x00\x00\x00\x00\x00\x42\x00\x0A\x07\x00\x00\x00\x09'
            b'\x78\x2D\x50\x75\x72\x70\x6F\x73\x65\x00\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_sans_attribute_names = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x37\x30\x33\x32\x35\x30\x62\x2D\x34\x64\x34\x30\x2D\x34\x64'
            b'\x65\x32\x2D\x39\x33\x61\x30\x2D\x63\x34\x39\x34\x61\x31\x64\x34'
            b'\x61\x65\x34\x30\x00\x00\x00\x00'
        )
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

        self.unique_identifier = '1703250b-4d40-4de2-93a0-c494a1d4ae40'
        self.attribute_names = [
            'Object Group',
            'Application Specific Information',
            'Contact Information',
            'x-Purpose'
        ]

    def tearDown(self):
        super(TestGetAttributesRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a GetAttributes request payload can be constructed with
        no arguments.
        """
        payloads.GetAttributesRequestPayload()

    def test_init_with_args(self):
        """
        Test that a GetAttributes request payload can be constructed with a
        valid value.
        """
        payloads.GetAttributesRequestPayload(
            'test-unique-identifier',
            ['test-attribute-name-1', 'test-attribute-name-2']
        )

    def test_unique_identifier(self):
        """
        Test that the unique_identifier attribute of a GetAttributes request
        payload can be properly set and retrieved.
        """
        payload = payloads.GetAttributesRequestPayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload._unique_identifier)

        payload.unique_identifier = 'test-unique-identifier'

        self.assertEqual('test-unique-identifier', payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value='test-unique-identifier',
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )

    def test_unique_identifier_with_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid ID is used to set
        the unique_identifier attribute of a GetAttributes request payload.
        """
        payload = payloads.GetAttributesRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "unique identifier must be a string",
            setattr,
            *args
        )

    def test_attribute_names(self):
        """
        Test that the attribute_names attribute of a GetAttributes request
        payload can be properly set and retrieved.
        """
        payload = payloads.GetAttributesRequestPayload()

        self.assertEqual(list(), payload.attribute_names)
        self.assertEqual(list(), payload._attribute_names)

        payload.attribute_names = [
            'test-attribute-name-1',
            'test-attribute-name-2'
        ]

        self.assertEqual(2, len(payload.attribute_names))
        self.assertEqual(2, len(payload._attribute_names))
        self.assertIn('test-attribute-name-1', payload.attribute_names)
        self.assertIn('test-attribute-name-2', payload.attribute_names)
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-1',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-2',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )

    def test_attribute_names_with_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid list is used to set
        the attribute_names attribute of a GetAttributes request payload.
        """
        payload = payloads.GetAttributesRequestPayload()
        args = (payload, 'attribute_names', 0)
        self.assertRaisesRegexp(
            TypeError,
            "attribute_names must be a list of strings",
            setattr,
            *args
        )

    def test_attribute_names_with_invalid_attribute_name(self):
        """
        Test that a TypeError is raised when an invalid attribute name is
        included in the list used to set the attribute_names attribute of a
        GetAttributes request payload.
        """
        payload = payloads.GetAttributesRequestPayload()
        args = (
            payload,
            'attribute_names',
            ['test-attribute-name-1', 0]
        )
        self.assertRaisesRegexp(
            TypeError,
            "attribute_names must be a list of strings; "
            "item 2 has type {0}".format(type(0)),
            setattr,
            *args
        )

    def test_attribute_names_with_duplicates(self):
        """
        Test that duplicate attribute names are silently removed when setting
        the attribute_names attribute of a GetAttributes request payload.
        """
        payload = payloads.GetAttributesRequestPayload()

        self.assertEqual(list(), payload.attribute_names)
        self.assertEqual(list(), payload._attribute_names)

        payload.attribute_names = [
            'test-attribute-name-1',
            'test-attribute-name-1',
            'test-attribute-name-2'
        ]

        self.assertEqual(2, len(payload.attribute_names))
        self.assertEqual(2, len(payload._attribute_names))
        self.assertIn('test-attribute-name-1', payload.attribute_names)
        self.assertIn('test-attribute-name-2', payload.attribute_names)
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-1',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )
        self.assertIn(
            primitives.TextString(
                value='test-attribute-name-2',
                tag=enums.Tags.ATTRIBUTE_NAME
            ),
            payload._attribute_names
        )

    def test_read(self):
        """
        Test that a GetAttributes request payload can be read from a data
        stream.
        """
        payload = payloads.GetAttributesRequestPayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attribute_names)

        payload.read(self.full_encoding)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value=self.unique_identifier,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )
        self.assertEqual(
            set(self.attribute_names),
            set(payload.attribute_names)
        )
        for attribute_name in self.attribute_names:
            self.assertIn(
                primitives.TextString(
                    value=attribute_name,
                    tag=enums.Tags.ATTRIBUTE_NAME
                ),
                payload._attribute_names
            )

    def test_read_with_no_unique_identifier(self):
        """
        Test that a GetAttributes request payload with no ID can be read
        from a data stream.
        """
        payload = payloads.GetAttributesRequestPayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attribute_names)

        payload.read(self.encoding_sans_unique_identifier)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(
            set(self.attribute_names),
            set(payload.attribute_names)
        )
        for attribute_name in self.attribute_names:
            self.assertIn(
                primitives.TextString(
                    value=attribute_name,
                    tag=enums.Tags.ATTRIBUTE_NAME
                ),
                payload._attribute_names
            )

    def test_read_with_no_attribute_names(self):
        """
        Test that a GetAttributes request payload with no attribute names
        can be read from a data stream.
        """
        payload = payloads.GetAttributesRequestPayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attribute_names)

        payload.read(self.encoding_sans_attribute_names)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value=self.unique_identifier,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )
        self.assertEqual(list(), payload.attribute_names)
        self.assertEqual(list(), payload._attribute_names)

    def test_read_with_no_content(self):
        """
        Test that a GetAttributes request payload with no ID or attribute
        names can be read from a data stream.
        """
        payload = payloads.GetAttributesRequestPayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attribute_names)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload.attribute_names)
        self.assertEqual(list(), payload._attribute_names)

    def test_write(self):
        """
        Test that a GetAttributes request payload can be written to a data
        stream.
        """
        payload = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_with_no_unique_identifier(self):
        """
        Test that a GetAttributes request payload with no ID can be written
        to a data stream.
        """
        payload = payloads.GetAttributesRequestPayload(
            None,
            self.attribute_names
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(
            len(self.encoding_sans_unique_identifier),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_sans_unique_identifier),
            str(stream)
        )

    def test_write_with_no_attribute_names(self):
        """
        Test that a GetAttributes request payload with no attribute names
        can be written to a data stream.
        """
        payload = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            None
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.encoding_sans_attribute_names), len(stream))
        self.assertEqual(str(self.encoding_sans_attribute_names), str(stream))

    def test_write_with_no_content(self):
        """
        Test that a GetAttributes request payload with no ID or attribute
        names can be written to a data stream.
        """
        payload = payloads.GetAttributesRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a GetAttributes request payload.
        """
        payload = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributesRequestPayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_repr_with_no_unique_identifier(self):
        """
        Test that repr can be applied to a GetAttributes request payload with
        no ID.
        """
        payload = payloads.GetAttributesRequestPayload(
            None,
            self.attribute_names
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributesRequestPayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_repr_with_no_attribute_names(self):
        """
        Test that repr can be applied to a GetAttributes request payload with
        no attribute names.
        """
        payload = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            None
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributesRequestPayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_repr_with_no_content(self):
        """
        Test that repr can be applied to a GetAttributes request payload with
        no ID or attribute names.
        """
        payload = payloads.GetAttributesRequestPayload(
            None,
            None
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        attribute_names = "attribute_names={0}".format(
            payload.attribute_names
        )
        expected = "GetAttributesRequestPayload({0}, {1})".format(
            unique_identifier,
            attribute_names
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetAttributes request payload.
        """
        payload = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        expected = str({
            'unique_identifier': self.unique_identifier,
            'attribute_names': self.attribute_names
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_str_with_no_id(self):
        """
        Test that str can be applied to a GetAttributes request payload with
        no ID.
        """
        payload = payloads.GetAttributesRequestPayload(
            None,
            self.attribute_names
        )
        expected = str({
            'unique_identifier': None,
            'attribute_names': self.attribute_names
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_str_with_no_attribute_names(self):
        """
        Test that str can be applied to a GetAttributes request payload with
        no attribute names.
        """
        payload = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            None
        )
        expected = str({
            'unique_identifier': self.unique_identifier,
            'attribute_names': list()
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_str_with_no_content(self):
        """
        Test that str can be applied to a GetAttributes request payload with
        no ID or attribute names.
        """
        payload = payloads.GetAttributesRequestPayload(
            None,
            None
        )
        expected = str({
            'unique_identifier': None,
            'attribute_names': list()
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributes request payloads with the same data.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_with_mixed_attribute_names(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributes request payload with the same attribute_name sets
        but with different attribute name orderings.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        self.attribute_names.reverse()
        b = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributes request payloads with different IDs.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributesRequestPayload(
            'invalid',
            self.attribute_names
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attribute_names(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributes request payloads with different attribute names.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            None
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        GetAttributes request payload to a non-GetAttributes request
        payload.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two GetAttributes request payloads with the same internal data.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributes request payloads with different IDs.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributesRequestPayload(
            'invalid',
            self.attribute_names
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attribute_names(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributes request payloads with different attribute names.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            None
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        GetAttributes request payload to a non-GetAttributes request
        payload.
        """
        a = payloads.GetAttributesRequestPayload(
            self.unique_identifier,
            self.attribute_names
        )
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)


class TestGetAttributesResponsePayload(testtools.TestCase):
    """
    Test suite for the GetAttributes response payload.
    """

    def setUp(self):
        super(TestGetAttributesResponsePayload, self).setUp()

        # Encodings taken from Sections 3.1.2 of the KMIP 1.1 testing
        # documentation.
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x01\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x37\x30\x33\x32\x35\x30\x62\x2D\x34\x64\x34\x30\x2D\x34\x64'
            b'\x65\x32\x2D\x39\x33\x61\x30\x2D\x63\x34\x39\x34\x61\x31\x64\x34'
            b'\x61\x65\x34\x30\x00\x00\x00\x00\x42\x00\x08\x01\x00\x00\x00\x28'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C\x4F\x62\x6A\x65\x63\x74\x20\x47'
            b'\x72\x6F\x75\x70\x00\x00\x00\x00\x42\x00\x0B\x07\x00\x00\x00\x06'
            b'\x47\x72\x6F\x75\x70\x31\x00\x00\x42\x00\x08\x01\x00\x00\x00\x58'
            b'\x42\x00\x0A\x07\x00\x00\x00\x20\x41\x70\x70\x6C\x69\x63\x61\x74'
            b'\x69\x6F\x6E\x20\x53\x70\x65\x63\x69\x66\x69\x63\x20\x49\x6E\x66'
            b'\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x03\x07\x00\x00\x00\x03\x73\x73\x6C\x00\x00\x00\x00\x00'
            b'\x42\x00\x02\x07\x00\x00\x00\x0F\x77\x77\x77\x2E\x65\x78\x61\x6D'
            b'\x70\x6C\x65\x2E\x63\x6F\x6D\x00\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x13\x43\x6F\x6E\x74\x61\x63\x74\x20'
            b'\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x03\x4A\x6F\x65\x00\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x09'
            b'\x78\x2D\x50\x75\x72\x70\x6F\x73\x65\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x0D\x64\x65\x6D\x6F\x6E\x73\x74\x72'
            b'\x61\x74\x69\x6F\x6E\x00\x00\x00'
        )
        self.encoding_sans_unique_identifier = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x01\x00\x42\x00\x08\x01\x00\x00\x00\x28'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0C\x4F\x62\x6A\x65\x63\x74\x20\x47'
            b'\x72\x6F\x75\x70\x00\x00\x00\x00\x42\x00\x0B\x07\x00\x00\x00\x06'
            b'\x47\x72\x6F\x75\x70\x31\x00\x00\x42\x00\x08\x01\x00\x00\x00\x58'
            b'\x42\x00\x0A\x07\x00\x00\x00\x20\x41\x70\x70\x6C\x69\x63\x61\x74'
            b'\x69\x6F\x6E\x20\x53\x70\x65\x63\x69\x66\x69\x63\x20\x49\x6E\x66'
            b'\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x42\x00\x0B\x01\x00\x00\x00\x28'
            b'\x42\x00\x03\x07\x00\x00\x00\x03\x73\x73\x6C\x00\x00\x00\x00\x00'
            b'\x42\x00\x02\x07\x00\x00\x00\x0F\x77\x77\x77\x2E\x65\x78\x61\x6D'
            b'\x70\x6C\x65\x2E\x63\x6F\x6D\x00\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x13\x43\x6F\x6E\x74\x61\x63\x74\x20'
            b'\x49\x6E\x66\x6F\x72\x6D\x61\x74\x69\x6F\x6E\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x03\x4A\x6F\x65\x00\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30\x42\x00\x0A\x07\x00\x00\x00\x09'
            b'\x78\x2D\x50\x75\x72\x70\x6F\x73\x65\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x07\x00\x00\x00\x0D\x64\x65\x6D\x6F\x6E\x73\x74\x72'
            b'\x61\x74\x69\x6F\x6E\x00\x00\x00'
        )
        self.encoding_sans_attributes = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x37\x30\x33\x32\x35\x30\x62\x2D\x34\x64\x34\x30\x2D\x34\x64'
            b'\x65\x32\x2D\x39\x33\x61\x30\x2D\x63\x34\x39\x34\x61\x31\x64\x34'
            b'\x61\x65\x34\x30\x00\x00\x00\x00'
        )

        self.unique_identifier = '1703250b-4d40-4de2-93a0-c494a1d4ae40'
        self.attributes = [
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName(
                    'Object Group'
                ),
                attribute_value=attributes.ObjectGroup('Group1')
            ),
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName(
                    'Application Specific Information'
                ),
                attribute_value=attributes.ApplicationSpecificInformation(
                    attributes.ApplicationNamespace('ssl'),
                    attributes.ApplicationData('www.example.com')
                )
            ),
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName(
                    'Contact Information'
                ),
                attribute_value=attributes.ContactInformation('Joe')
            ),
            objects.Attribute(
                attribute_name=objects.Attribute.AttributeName('x-Purpose'),
                attribute_value=primitives.TextString('demonstration')
            )
        ]

    def tearDown(self):
        super(TestGetAttributesResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a GetAttributes response payload can be constructed.
        """
        payloads.GetAttributesResponsePayload()

    def test_init_with_args(self):
        """
        Test that a GetAttributes response payload can be constructed with a
        valid value.
        """
        payloads.GetAttributesResponsePayload(
            'test-unique-identifier',
            [objects.Attribute(), objects.Attribute()]
        )

    def test_unique_identifier(self):
        """
        Test that the unique_identifier attribute of a GetAttributes response
        payload can be properly set and retrieved.
        """
        payload = payloads.GetAttributesResponsePayload()

        self.assertIsNone(payload.unique_identifier)
        self.assertIsNone(payload._unique_identifier)

        payload.unique_identifier = 'test-unique-identifier'

        self.assertEqual('test-unique-identifier', payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value='test-unique-identifier',
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )

    def test_unique_identifier_with_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid ID is used to set
        the unique_identifier attribute of a GetAttributes response payload.
        """
        payload = payloads.GetAttributesResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegexp(
            TypeError,
            "unique identifier must be a string",
            setattr,
            *args
        )

    def test_attributes(self):
        """
        Test that the attributes attribute of a GetAttributes response
        payload can be properly set and retrieved.
        """
        payload = payloads.GetAttributesResponsePayload()

        self.assertEqual(list(), payload.attributes)
        self.assertEqual(list(), payload._attributes)

        payload.attributes = [
            objects.Attribute(),
            objects.Attribute()
        ]

        self.assertEqual(2, len(payload.attributes))
        self.assertEqual(2, len(payload._attributes))
        for attribute in payload._attributes:
            self.assertIsInstance(attribute, objects.Attribute)

    def test_attributes_with_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid list is used to set
        the attributes attribute of a GetAttributes response payload.
        """
        payload = payloads.GetAttributesResponsePayload()
        args = (payload, 'attributes', 0)
        self.assertRaisesRegexp(
            TypeError,
            "attributes must be a list of attribute objects",
            setattr,
            *args
        )

    def test_attributes_with_invalid_attribute(self):
        """
        Test that a TypeError is raised when an invalid attribute is included
        in the list used to set the attributes attribute of a GetAttributes
        response payload.
        """
        payload = payloads.GetAttributesResponsePayload()
        args = (
            payload,
            'attributes',
            [objects.Attribute(), 0]
        )
        self.assertRaisesRegexp(
            TypeError,
            "attributes must be a list of attribute objects; "
            "item 2 has type {0}".format(type(0)),
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a GetAttributes response payload can be read from a data
        stream.
        """
        payload = payloads.GetAttributesResponsePayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attributes)

        payload.read(self.full_encoding)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value=self.unique_identifier,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )
        self.assertEqual(
            len(self.attributes),
            len(payload.attributes)
        )
        for attribute in self.attributes:
            self.assertIn(
                attribute,
                payload._attributes
            )

    def test_read_with_no_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error gets raised when attempting to
        read a GetAttributes response encoding with no ID data.
        """
        payload = payloads.GetAttributesResponsePayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attributes)

        args = (self.encoding_sans_unique_identifier, )
        self.assertRaisesRegexp(
            exceptions.InvalidKmipEncoding,
            "expected GetAttributes response unique identifier not found",
            payload.read,
            *args
        )

    def test_read_with_no_attributes(self):
        """
        Test that a GetAttributes response payload without attribute name
        data can be read from a data stream.
        """
        payload = payloads.GetAttributesResponsePayload()

        self.assertEqual(None, payload._unique_identifier)
        self.assertEqual(list(), payload._attributes)

        payload.read(self.encoding_sans_attributes)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(
            primitives.TextString(
                value=self.unique_identifier,
                tag=enums.Tags.UNIQUE_IDENTIFIER
            ),
            payload._unique_identifier
        )
        self.assertEqual(list(), payload.attributes)
        self.assertEqual(list(), payload._attributes)

    def test_write(self):
        """
        Test that a GetAttributes response payload can be written to a data
        stream.
        """
        payload = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_with_no_unique_identifier(self):
        """
        Test that a GetAttributes request payload with no ID can be written
        to a data stream.
        """
        payload = payloads.GetAttributesResponsePayload(
            None,
            self.attributes
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The GetAttributes response unique identifier is required.",
            payload.write,
            *args
        )

    def test_write_with_no_attribute_names(self):
        """
        Test that a GetAttributes response payload with no attribute name
        data can be written to a data stream.
        """
        payload = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            None
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.encoding_sans_attributes), len(stream))
        self.assertEqual(str(self.encoding_sans_attributes), str(stream))

    def test_repr(self):
        """
        Test that repr can be applied to a GetAttributes response payload.
        """
        payload = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        unique_identifier = "unique_identifier={0}".format(
            payload.unique_identifier
        )
        payload_attributes = "attributes={0}".format(
            payload.attributes
        )
        expected = "GetAttributesResponsePayload({0}, {1})".format(
            unique_identifier,
            payload_attributes
        )
        observed = repr(payload)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a GetAttributes response payload.
        """
        payload = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        expected = str({
            'unique_identifier': self.unique_identifier,
            'attributes': self.attributes
        })
        observed = str(payload)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        GetAttributes response payloads with the same data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributes response payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = payloads.GetAttributesResponsePayload(
            'invalid',
            self.attributes
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attributes(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributes response payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        reversed_attributes = copy.deepcopy(self.attributes)
        reversed_attributes.reverse()
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            reversed_attributes
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attributes_count(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributes response payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            list()
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attributes_types(self):
        """
        Test that the equality operator returns False when comparing two
        GetAttributes response payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            None
        )
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        GetAttributes response payload to a non-GetAttributes response
        payload.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two GetAttributes response payloads with the same internal data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        GetAttributes request payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = payloads.GetAttributesResponsePayload(
            'invalid',
            self.attributes
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attributes(self):
        """
        Test that the inequality operator returns False when comparing two
        GetAttributes response payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        reversed_attributes = copy.deepcopy(self.attributes)
        reversed_attributes.reverse()
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            reversed_attributes
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attributes_count(self):
        """
        Test that the inequality operator returns False when comparing two
        GetAttributes response payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            list()
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attributes_types(self):
        """
        Test that the inequality operator returns False when comparing two
        GetAttributes response payloads with different data.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            None
        )
        b = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        GetAttributes response payload to a non-GetAttributes response
        payload.
        """
        a = payloads.GetAttributesResponsePayload(
            self.unique_identifier,
            self.attributes
        )
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)
