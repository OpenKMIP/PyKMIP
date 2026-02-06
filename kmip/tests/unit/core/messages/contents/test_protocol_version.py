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

import testtools

from kmip.core import enums
from kmip.core.messages import contents
from kmip.core import utils

class TestProtocolVersion(testtools.TestCase):

    def setUp(self):
        super(TestProtocolVersion, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 3.1.1.
        #
        # This encoding matches the following set of values:
        # ProtocolVersion
        #     ProtocolVersionMajor - 1
        #     ProtocolVersionMinor - 1

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x69\x01\x00\x00\x00\x20'
            b'\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        self.encoding_no_major_number = utils.BytearrayStream(
            b'\x42\x00\x69\x01\x00\x00\x00\x10'
            b'\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        self.encoding_no_minor_number = utils.BytearrayStream(
            b'\x42\x00\x69\x01\x00\x00\x00\x10'
            b'\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestProtocolVersion, self).tearDown()

    def test_init(self):
        """
        Test that a ProtocolVersion struct can be constructed with no
        arguments.
        """
        struct = contents.ProtocolVersion()

        self.assertEqual(None, struct.major)
        self.assertEqual(None, struct.minor)

    def test_init_with_args(self):
        """
        Test that a ProtocolVersion struct can be constructed with valid
        values.
        """
        struct = contents.ProtocolVersion(1, 1)

        self.assertEqual(1, struct.major)
        self.assertEqual(1, struct.minor)

    def test_invalid_protocol_version_major(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the major protocol version number of a ProtocolVersion struct.
        """
        struct = contents.ProtocolVersion()
        args = (struct, 'major', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Major protocol version number must be an integer.",
            setattr,
            *args
        )

    def test_invalid_protocol_version_minor(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the minor protocol version number of a ProtocolVersion struct.
        """
        struct = contents.ProtocolVersion()
        args = (struct, 'minor', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Minor protocol version number must be an integer.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a ProtocolVersion struct can be read from a data stream.
        """
        struct = contents.ProtocolVersion()

        self.assertEqual(None, struct.major)
        self.assertEqual(None, struct.minor)

        struct.read(self.full_encoding)

        self.assertEqual(1, struct.major)
        self.assertEqual(1, struct.minor)

    def test_read_missing_major_number(self):
        """
        Test that a ValueError gets raised when a required ProtocolVersion
        struct attribute is missing from the struct encoding.
        """
        struct = contents.ProtocolVersion()
        args = (self.encoding_no_major_number, )
        self.assertRaisesRegex(
            ValueError,
            "Invalid encoding missing the major protocol version number.",
            struct.read,
            *args
        )

    def test_read_missing_minor_number(self):
        """
        Test that a ValueError gets raised when a required ProtocolVersion
        struct attribute is missing from the struct encoding.
        """
        struct = contents.ProtocolVersion()
        args = (self.encoding_no_minor_number, )
        self.assertRaisesRegex(
            ValueError,
            "Invalid encoding missing the minor protocol version number.",
            struct.read,
            *args
        )

    def test_write(self):
        """
        Test that a ProtocolVersion struct can be written to a data stream.
        """
        struct = contents.ProtocolVersion(1, 1)
        stream = utils.BytearrayStream()
        struct.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_major_number(self):
        """
        Test that a ValueError gets raised when a required ProtocolVersion
        struct attribute is missing when encoding the struct.
        """
        struct = contents.ProtocolVersion(None, 1)
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the major protocol version number.",
            struct.write,
            *args
        )

    def test_write_missing_minor_number(self):
        """
        Test that a ValueError gets raised when a required ProtocolVersion
        struct attribute is missing when encoding the struct.
        """
        struct = contents.ProtocolVersion(1, None)
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Invalid struct missing the minor protocol version number.",
            struct.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ProtocolVersion structs with the same data.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(1, 0)

        self.assertTrue(a == b)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        ProtocolVersion structs with different data.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(0, 1)

        self.assertFalse(a == b)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        ProtocolVersion structs with different types.
        """
        a = contents.ProtocolVersion(1, 0)
        b = "invalid"

        self.assertFalse(a == b)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        ProtocolVersion structs with the same data.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(1, 0)

        self.assertFalse(a != b)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        ProtocolVersion structs with different data.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(0, 1)

        self.assertTrue(a != b)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        ProtocolVersion structs with different types.
        """
        a = contents.ProtocolVersion(1, 0)
        b = "invalid"

        self.assertTrue(a != b)

    def test_less_than(self):
        """
        Test that the less than operator correctly returns True/False when
        comparing two different ProtocolVersions.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(1, 1)
        c = contents.ProtocolVersion(2, 0)
        d = contents.ProtocolVersion(0, 2)

        self.assertTrue(a < b)
        self.assertFalse(b < a)
        self.assertFalse(a < a)
        self.assertTrue(a < c)
        self.assertFalse(c < a)
        self.assertFalse(c < d)
        self.assertTrue(d < c)

        # A direct call to __lt__ is required here due to differences in how
        # Python 2 and Python 3 treat comparison operators.
        self.assertEqual(NotImplemented, a.__lt__('invalid'))

    def test_greater_than(self):
        """
        Test that the greater than operator correctly returns True/False when
        comparing two different ProtocolVersions.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(1, 1)
        c = contents.ProtocolVersion(2, 0)
        d = contents.ProtocolVersion(0, 2)

        self.assertFalse(a > b)
        self.assertTrue(b > a)
        self.assertFalse(a > a)
        self.assertFalse(a > c)
        self.assertTrue(c > a)
        self.assertTrue(c > d)
        self.assertFalse(d > c)

        # A direct call to __gt__ is required here due to differences in how
        # Python 2 and Python 3 treat comparison operators.
        self.assertEqual(NotImplemented, a.__gt__('invalid'))

    def test_less_than_or_equal(self):
        """
        Test that the less than or equal operator correctly returns True/False
        when comparing two different ProtocolVersions.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(1, 1)
        c = contents.ProtocolVersion(2, 0)
        d = contents.ProtocolVersion(0, 2)

        self.assertTrue(a <= b)
        self.assertFalse(b <= a)
        self.assertTrue(a <= a)
        self.assertTrue(a <= c)
        self.assertFalse(c <= a)
        self.assertFalse(c <= d)
        self.assertTrue(d <= c)

        # A direct call to __le__ is required here due to differences in how
        # Python 2 and Python 3 treat comparison operators.
        self.assertEqual(NotImplemented, a.__le__('invalid'))

    def test_greater_than_or_equal(self):
        """
        Test that the greater than or equal operator correctly returns
        True/False when comparing two different ProtocolVersions.
        """
        a = contents.ProtocolVersion(1, 0)
        b = contents.ProtocolVersion(1, 1)
        c = contents.ProtocolVersion(2, 0)
        d = contents.ProtocolVersion(0, 2)

        self.assertFalse(a >= b)
        self.assertTrue(b >= a)
        self.assertTrue(a >= a)
        self.assertFalse(a >= c)
        self.assertTrue(c >= a)
        self.assertTrue(c >= d)
        self.assertFalse(d >= c)

        # A direct call to __ge__ is required here due to differences in how
        # Python 2 and Python 3 treat comparison operators.
        self.assertEqual(NotImplemented, a.__ge__('invalid'))

    def test_repr(self):
        """
        Test that repr can be applied to a ProtocolVersion struct.
        """
        struct = contents.ProtocolVersion(1, 0)

        self.assertEqual(
            "ProtocolVersion(major=1, minor=0)",
            "{}".format(repr(struct))
        )

    def test_str(self):
        """
        Test that str can be applied to a ProtocolVersion struct.
        """
        struct = contents.ProtocolVersion(1, 0)

        self.assertEqual("1.0", str(struct))

class TestContents(testtools.TestCase):

    def setUp(self):
        super(TestContents, self).setUp()

    def tearDown(self):
        super(TestContents, self).tearDown()

    def test_protocol_version_to_kmip_version_kmip_1_0(self):
        """
        Test the conversion from ProtocolVersion(1, 0) to KMIPVersion.KMIP_1_0.
        """
        result = contents.protocol_version_to_kmip_version(
            contents.ProtocolVersion(1, 0)
        )
        self.assertEqual(result, enums.KMIPVersion.KMIP_1_0)

    def test_protocol_version_to_kmip_version_kmip_1_1(self):
        """
        Test the conversion from ProtocolVersion(1, 1) to KMIPVersion.KMIP_1_1.
        """
        result = contents.protocol_version_to_kmip_version(
            contents.ProtocolVersion(1, 1)
        )
        self.assertEqual(result, enums.KMIPVersion.KMIP_1_1)

    def test_protocol_version_to_kmip_version_kmip_1_2(self):
        """
        Test the conversion from ProtocolVersion(1, 2) to KMIPVersion.KMIP_1_2.
        """
        result = contents.protocol_version_to_kmip_version(
            contents.ProtocolVersion(1, 2)
        )
        self.assertEqual(result, enums.KMIPVersion.KMIP_1_2)

    def test_protocol_version_to_kmip_version_kmip_1_3(self):
        """
        Test the conversion from ProtocolVersion(1, 3) to KMIPVersion.KMIP_1_3.
        """
        result = contents.protocol_version_to_kmip_version(
            contents.ProtocolVersion(1, 3)
        )
        self.assertEqual(result, enums.KMIPVersion.KMIP_1_3)

    def test_protocol_version_to_kmip_version_kmip_1_4(self):
        """
        Test the conversion from ProtocolVersion(1, 4) to KMIPVersion.KMIP_1_4.
        """
        result = contents.protocol_version_to_kmip_version(
            contents.ProtocolVersion(1, 4)
        )
        self.assertEqual(result, enums.KMIPVersion.KMIP_1_4)

    def test_protocol_version_to_kmip_version_invalid_minor(self):
        """
        Test the conversion from invalid ProtocolVersion minor value to None.
        """
        result = contents.protocol_version_to_kmip_version(
            contents.ProtocolVersion(1, 5)
        )
        self.assertIsNone(result)

    def test_protocol_version_to_kmip_version_invalid_major(self):
        """
        Test the conversion from invalid ProtocolVersion major value to None.
        """
        result = contents.protocol_version_to_kmip_version(
            contents.ProtocolVersion(9, 5)
        )
        self.assertIsNone(result)
