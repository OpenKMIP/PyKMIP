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

from testtools import TestCase

from kmip.core.objects import ExtensionInformation
from kmip.core.objects import ExtensionName
from kmip.core.objects import ExtensionTag
from kmip.core.objects import ExtensionType

from kmip.core.utils import BytearrayStream

class TestExtensionInformation(TestCase):
    """
    A test suite for the ExtensionInformation class.

    Test encodings obtained from Section 12.2 of the KMIP 1.1 Test Cases
    documentation.
    """

    def setUp(self):
        super(TestExtensionInformation, self).setUp()

        self.extension_name_b = ExtensionName('ACME LOCATION')
        self.extension_name_c = ExtensionName('ACME LOCATION')
        self.extension_name_d = ExtensionName('ACME ZIP CODE')

        self.extension_tag_c = ExtensionTag(5548545)
        self.extension_tag_d = ExtensionTag(5548546)

        self.extension_type_c = ExtensionType(7)
        self.extension_type_d = ExtensionType(2)

        self.encoding_a = BytearrayStream(
            b'\x42\x00\xA4\x01\x00\x00\x00\x08\x42\x00\xA5\x07\x00\x00\x00'
            b'\x00')
        self.encoding_b = BytearrayStream(
            b'\x42\x00\xA4\x01\x00\x00\x00\x18\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x4C\x4F\x43\x41\x54\x49\x4F\x4E\x00\x00'
            b'\x00')
        self.encoding_c = BytearrayStream(
            b'\x42\x00\xA4\x01\x00\x00\x00\x38\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x4C\x4F\x43\x41\x54\x49\x4F\x4E\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x01\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00'
            b'\x00')
        self.encoding_d = BytearrayStream(
            b'\x42\x00\xA4\x01\x00\x00\x00\x38\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x5A\x49\x50\x20\x43\x4F\x44\x45\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x02\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00'
            b'\x00')

    def tearDown(self):
        super(TestExtensionInformation, self).tearDown()

    def _test_init(self):
        pass

    def test_init_with_none(self):
        ExtensionInformation()

    def test_init_with_args(self):
        ExtensionInformation(
            extension_name=ExtensionName(),
            extension_tag=ExtensionTag(),
            extension_type=ExtensionType())

    def test_validate_with_invalid_extension_name(self):
        """
        Test that a TypeError exception is raised when an invalid
        ExtensionName is used to construct an ExtensionInformation object.
        """
        kwargs = {'extension_name': 'invalid'}
        self.assertRaisesRegex(
            TypeError, "invalid extension name",
            ExtensionInformation, **kwargs)

    def test_validate_with_invalid_extension_tag(self):
        """
        Test that a TypeError exception is raised when an invalid
        ExtensionTag is used to construct an ExtensionInformation object.
        """
        kwargs = {'extension_tag': 'invalid'}
        self.assertRaisesRegex(
            TypeError, "invalid extension tag",
            ExtensionInformation, **kwargs)

    def test_validate_with_invalid_extension_type(self):
        """
        Test that a TypeError exception is raised when an invalid
        ExtensionType is used to construct an ExtensionInformation object.
        """
        kwargs = {'extension_type': 'invalid'}
        self.assertRaisesRegex(
            TypeError, "invalid extension type",
            ExtensionInformation, **kwargs)

    def _test_read(self, stream, extension_name, extension_tag,
                   extension_type):
        extension_information = ExtensionInformation()
        extension_information.read(stream)

        if extension_name is None:
            extension_name = ExtensionName()

        msg = "extension name encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            extension_name,
            extension_information.extension_name)
        self.assertEqual(
            extension_name,
            extension_information.extension_name, msg)

        msg = "extension tag encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            extension_tag,
            extension_information.extension_tag)
        self.assertEqual(
            extension_tag,
            extension_information.extension_tag, msg)

        msg = "extension type encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            extension_type,
            extension_information.extension_type)
        self.assertEqual(
            extension_type,
            extension_information.extension_type, msg)

    def test_read_with_none(self):
        """
        Test that an ExtensionInformation object with no data can be read from
        a data stream.
        """
        self._test_read(self.encoding_a, None, None, None)

    def test_read_with_partial_args(self):
        """
        Test that an ExtensionInformation object with some data can be read
        from a data stream.
        """
        self._test_read(self.encoding_b, self.extension_name_b, None, None)

    def test_read_with_multiple_args(self):
        """
        Test that an ExtensionInformation object with data can be read from a
        data stream.
        """
        self._test_read(self.encoding_c, self.extension_name_c,
                        self.extension_tag_c, self.extension_type_c)

    def _test_write(self, stream_expected, extension_name, extension_tag,
                    extension_type):
        stream_observed = BytearrayStream()
        extension_information = ExtensionInformation(
            extension_name=extension_name,
            extension_tag=extension_tag,
            extension_type=extension_type)
        extension_information.write(stream_observed)

        length_expected = len(stream_expected)
        length_observed = len(stream_observed)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, observed {1}".format(
            length_expected, length_observed)
        self.assertEqual(length_expected, length_observed, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nobserved:\n{1}".format(
            stream_expected, stream_observed)
        self.assertEqual(stream_expected, stream_observed, msg)

    def test_write_with_none(self):
        """
        Test that an ExtensionInformation object with no data can be written
        to a data stream.
        """
        self._test_write(self.encoding_a, None, None, None)

    def test_write_with_partial_args(self):
        """
        Test that an ExtensionInformation object with some data can be written
        to a data stream.
        """
        self._test_write(self.encoding_b, self.extension_name_b, None, None)

    def test_write_with_multiple_args(self):
        """
        Test that an ExtensionInformation object with data can be written to
        a data stream.
        """
        self._test_write(self.encoding_c, self.extension_name_c,
                         self.extension_tag_c, self.extension_type_c)

    def _test_create(self, extension_name, extension_tag, extension_type):
        extension_information = ExtensionInformation.create(
            extension_name=extension_name,
            extension_tag=extension_tag,
            extension_type=extension_type)

        self.assertIsInstance(extension_information, ExtensionInformation)

        expected = ExtensionName(extension_name)
        observed = extension_information.extension_name

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = ExtensionTag(extension_tag)
        observed = extension_information.extension_tag

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = ExtensionType(extension_type)
        observed = extension_information.extension_type

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_create_with_none(self):
        """
        Test that an ExtensionInformation object with no data can be created
        using the create class method.
        """
        self._test_create(None, None, None)

    def test_create_with_args(self):
        """
        Test that an ExtensionInformation object with data can be created
        using the create class method.
        """
        self._test_create('ACME LOCATION', 5548545, 7)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ExtensionInformation objects with the same internal data.
        """
        a = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)
        b = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        ExtensionInformation objects with no internal data.
        """
        a = ExtensionInformation()
        b = ExtensionInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        ExtensionInformation objects with different sets of internal data.
        """
        a = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)
        b = ExtensionInformation()

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing an
        ExtensionInformation object with a non-ExtensionInformation object.
        """
        a = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ExtensionInformation objects with the same internal data.
        """
        a = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)
        b = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing two
        ExtensionInformation objects with no internal data.
        """
        a = ExtensionInformation()
        b = ExtensionInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        ExtensionInformation objects with the different sets of internal data.
        """
        a = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)
        b = ExtensionInformation()

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing an
        ExtensionInformation object with a non-ExtensionInformation object.
        """
        a = ExtensionInformation(
            extension_name=self.extension_name_c,
            extension_tag=self.extension_tag_c,
            extension_type=self.extension_type_c)
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr_with_no_data(self):
        """
        Test that the representation of an ExtensionInformation object with no
        data is formatted properly and can be used by eval to create a new
        ExtensionInformation object identical to the original.
        """
        extension_information = ExtensionInformation()

        expected = "ExtensionInformation("
        expected += "extension_name=ExtensionName(value=''), "
        expected += "extension_tag=None, "
        expected += "extension_type=None)"
        observed = repr(extension_information)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = extension_information
        observed = eval(repr(extension_information))

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_repr_with_data(self):
        """
        Test that the representation of an ExtensionInformation object with
        data is formatted properly and can be used by eval to create a new
        ExtensionInformation object identical to the original.
        """
        extension_information = ExtensionInformation(
            extension_name=ExtensionName('ACME LOCATION'),
            extension_tag=ExtensionTag(5548545),
            extension_type=ExtensionType(7))

        expected = "ExtensionInformation("
        expected += "extension_name=ExtensionName(value='ACME LOCATION'), "
        expected += "extension_tag=ExtensionTag(value=5548545), "
        expected += "extension_type=ExtensionType(value=7))"
        observed = repr(extension_information)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = extension_information
        observed = eval(repr(extension_information))

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_str_with_no_data(self):
        """
        Test that the string representation of an ExtensionInformation object
        is formatted properly when there is no internal data.
        """
        extension_information = ExtensionInformation()

        expected = "ExtensionInformation("
        expected += "extension_name=ExtensionName(value=''), "
        expected += "extension_tag=None, "
        expected += "extension_type=None)"
        observed = str(extension_information)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_str_with_data(self):
        """
        Test that the string representation of an ExtensionInformation object
        is formatted properly when there is internal data.
        """
        extension_information = ExtensionInformation(
            extension_name=ExtensionName('ACME LOCATION'),
            extension_tag=ExtensionTag(5548545),
            extension_type=ExtensionType(7))

        expected = "ExtensionInformation("
        expected += "extension_name=ExtensionName(value='ACME LOCATION'), "
        expected += "extension_tag=ExtensionTag(value=5548545), "
        expected += "extension_type=ExtensionType(value=7))"
        observed = str(extension_information)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)
