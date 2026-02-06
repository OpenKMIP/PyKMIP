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

import testtools

from kmip.core import exceptions
from kmip.core import primitives
from kmip.core import utils

class TestBigInteger(testtools.TestCase):

    def setUp(self):
        super(TestBigInteger, self).setUp()

        # Encodings and values taken from Sections 5.1, 13.3 and 18.2 of the
        # KMIP 1.1 testing documentation.
        self.value_positive = int(
            '74570697368583857894612671217453076717255131155396275504564761583'
            '15899148268876158582639566401239193216235126746176682996459367959'
            '36793366865165780165066709295778050045731105353780121783233185565'
            '36420486996200625818559496541368747791032257508332162004121562017'
            '72772159096834586599791505043949123930975157363117571140205992199'
            '59827555693853730430222361950476764952992840295849053634702315874'
            '87536235568284292445148693873502200712082861995083783995720224553'
            '38838078028390162249415071016709848797960500969432640102143437177'
            '60785867099769472998343832254180691121895373077720157164352949735'
            '8482684822484513735382434823977')
        self.value_negative = -1000

        self.encoding_zero = utils.BytearrayStream(
            b'\x42\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.encoding_positive = utils.BytearrayStream(
            b'\x42\x00\x00\x04\x00\x00\x01\x00\x3B\x12\x45\x5D\x53\xC1\x81\x65'
            b'\x16\xC5\x18\x49\x3F\x63\x98\xAA\xFA\x72\xB1\x7D\xFA\x89\x4D\xB8'
            b'\x88\xA7\xD4\x8C\x0A\x47\xF6\x25\x79\xA4\xE6\x44\xF8\x6D\xA7\x11'
            b'\xFE\xC8\x50\xCD\xD9\xDB\xBD\x17\xF6\x9A\x44\x3D\x2E\xC1\xDD\x60'
            b'\xD3\xC6\x18\xFA\x74\xCD\xE5\xFD\xAF\xAB\xD6\xBA\xA2\x6E\xB0\xA3'
            b'\xAD\xB4\xDE\xF6\x48\x0F\xB1\x21\x8C\xD3\xB0\x83\xE2\x52\xE8\x85'
            b'\xB6\xF0\x72\x9F\x98\xB2\x14\x4D\x2B\x72\x29\x3E\x1B\x11\xD7\x33'
            b'\x93\xBC\x41\xF7\x5B\x15\xEE\x3D\x75\x69\xB4\x99\x5E\xD1\xA1\x44'
            b'\x25\xDA\x43\x19\xB7\xB2\x6B\x0E\x8F\xEF\x17\xC3\x75\x42\xAE\x5C'
            b'\x6D\x58\x49\xF8\x72\x09\x56\x7F\x39\x25\xA4\x7B\x01\x6D\x56\x48'
            b'\x59\x71\x7B\xC5\x7F\xCB\x45\x22\xD0\xAA\x49\xCE\x81\x6E\x5B\xE7'
            b'\xB3\x08\x81\x93\x23\x6E\xC9\xEF\xFF\x14\x08\x58\x04\x5B\x73\xC5'
            b'\xD7\x9B\xAF\x38\xF7\xC6\x7F\x04\xC5\xDC\xF0\xE3\x80\x6A\xD9\x82'
            b'\xD1\x25\x90\x58\xC3\x47\x3E\x84\x71\x79\xA8\x78\xF2\xC6\xB3\xBD'
            b'\x96\x8F\xB9\x9E\xA4\x6E\x91\x85\x89\x2F\x36\x76\xE7\x89\x65\xC2'
            b'\xAE\xD4\x87\x7B\xA3\x91\x7D\xF0\x7C\x5E\x92\x74\x74\xF1\x9E\x76'
            b'\x4B\xA6\x1D\xC3\x8D\x63\xBF\x29')
        self.encoding_negative = utils.BytearrayStream(
            b'\x42\x00\x00\x04\x00\x00\x00\x08\xFF\xFF\xFF\xFF\xFF\xFF\xFC'
            b'\x18')
        self.encoding_bad_length = utils.BytearrayStream(
            b'\x42\x00\x00\x04\x00\x00\x01\x01\x3B\x12\x45\x5D\x53\xC1\x81\x65'
            b'\x16\xC5\x18\x49\x3F\x63\x98\xAA\xFA\x72\xB1\x7D\xFA\x89\x4D\xB8'
            b'\x88\xA7\xD4\x8C\x0A\x47\xF6\x25\x79\xA4\xE6\x44\xF8\x6D\xA7\x11'
            b'\xFE\xC8\x50\xCD\xD9\xDB\xBD\x17\xF6\x9A\x44\x3D\x2E\xC1\xDD\x60'
            b'\xD3\xC6\x18\xFA\x74\xCD\xE5\xFD\xAF\xAB\xD6\xBA\xA2\x6E\xB0\xA3'
            b'\xAD\xB4\xDE\xF6\x48\x0F\xB1\x21\x8C\xD3\xB0\x83\xE2\x52\xE8\x85'
            b'\xB6\xF0\x72\x9F\x98\xB2\x14\x4D\x2B\x72\x29\x3E\x1B\x11\xD7\x33'
            b'\x93\xBC\x41\xF7\x5B\x15\xEE\x3D\x75\x69\xB4\x99\x5E\xD1\xA1\x44'
            b'\x25\xDA\x43\x19\xB7\xB2\x6B\x0E\x8F\xEF\x17\xC3\x75\x42\xAE\x5C'
            b'\x6D\x58\x49\xF8\x72\x09\x56\x7F\x39\x25\xA4\x7B\x01\x6D\x56\x48'
            b'\x59\x71\x7B\xC5\x7F\xCB\x45\x22\xD0\xAA\x49\xCE\x81\x6E\x5B\xE7'
            b'\xB3\x08\x81\x93\x23\x6E\xC9\xEF\xFF\x14\x08\x58\x04\x5B\x73\xC5'
            b'\xD7\x9B\xAF\x38\xF7\xC6\x7F\x04\xC5\xDC\xF0\xE3\x80\x6A\xD9\x82'
            b'\xD1\x25\x90\x58\xC3\x47\x3E\x84\x71\x79\xA8\x78\xF2\xC6\xB3\xBD'
            b'\x96\x8F\xB9\x9E\xA4\x6E\x91\x85\x89\x2F\x36\x76\xE7\x89\x65\xC2'
            b'\xAE\xD4\x87\x7B\xA3\x91\x7D\xF0\x7C\x5E\x92\x74\x74\xF1\x9E\x76'
            b'\x4B\xA6\x1D\xC3\x8D\x63\xBF\x29')

    def tearDown(self):
        super(TestBigInteger, self).tearDown()

    def test_init(self):
        """
        Test that a BigInteger can be instantiated.
        """
        big_int = primitives.BigInteger(1)
        self.assertEqual(1, big_int.value)

    def test_init_unset(self):
        """
        Test that a BigInteger can be instantiated with no input.
        """
        big_int = primitives.BigInteger()
        self.assertEqual(0, big_int.value)

    def test_init_big_positive(self):
        """
        Test that a BigInteger can be instantiated with large positive input.
        """
        big_int = primitives.BigInteger(self.value_positive)
        self.assertEqual(self.value_positive, big_int.value)

    def test_init_negative(self):
        """
        Test that a BigInteger can be instantiated with negative input.
        """
        big_int = primitives.BigInteger(self.value_negative)
        self.assertEqual(self.value_negative, big_int.value)

    def test_validate_on_invalid(self):
        """
        Test that a TypeError is thrown on input of invalid type (e.g., str).
        """
        self.assertRaises(TypeError, primitives.BigInteger, 'invalid')

    def test_read_zero(self):
        """
        Test that a BigInteger representing the value 0 can be read from a
        byte stream.
        """
        big_int = primitives.BigInteger()
        big_int.read(self.encoding_zero)
        self.assertEqual(0, big_int.value)

    def test_read_positive(self):
        """
        Test that a BigInteger representing a big positive value can be read
        from a byte stream.
        """
        big_int = primitives.BigInteger()
        big_int.read(self.encoding_positive)
        self.assertEqual(self.value_positive, big_int.value)

    def test_read_negative(self):
        """
        Test that a BigInteger representing a negative value can be read from
        a byte stream.
        """
        big_int = primitives.BigInteger()
        big_int.read(self.encoding_negative)
        self.assertEqual(self.value_negative, big_int.value)

    def test_read_on_invalid_length(self):
        """
        Test that an InvalidPrimitiveLength exception is thrown when attempting
        to decode a BigInteger with an invalid length.
        """
        big_int = primitives.BigInteger()
        self.assertRaises(
            exceptions.InvalidPrimitiveLength, big_int.read,
            self.encoding_bad_length)

    def test_write_zero(self):
        """
        Test that a BigInteger representing the value 0 can be read written to
        a byte stream.
        """
        stream = utils.BytearrayStream()
        big_int = primitives.BigInteger()
        big_int.write(stream)
        self.assertEqual(self.encoding_zero, stream)

    def test_write_positive(self):
        """
        Test that a BigInteger representing a big positive value can be written
        to a byte stream.
        """
        stream = utils.BytearrayStream()
        big_int = primitives.BigInteger(self.value_positive)
        big_int.write(stream)
        self.assertEqual(self.encoding_positive, stream)

    def test_write_negative(self):
        """
        Test that a BigInteger representing a negative value can be written to
        a byte stream.
        """
        stream = utils.BytearrayStream()
        big_int = primitives.BigInteger(self.value_negative)
        big_int.write(stream)
        self.assertEqual(self.encoding_negative, stream)

    def test_repr(self):
        """
        Test that the representation of a BigInteger is formatted properly.
        """
        long_int = primitives.BigInteger()
        value = "value={0}".format(long_int.value)
        tag = "tag={0}".format(long_int.tag)
        self.assertEqual(
            "BigInteger({0}, {1})".format(value, tag), repr(long_int))

    def test_str(self):
        """
        Test that the string representation of a BigInteger is formatted
        properly.
        """
        self.assertEqual("0", str(primitives.BigInteger()))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        BigIntegers.
        """
        a = primitives.BigInteger(1)
        b = primitives.BigInteger(1)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        BigIntegers.
        """
        a = primitives.BigInteger()
        b = primitives.BigInteger()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        BigIntegers with different values.
        """
        a = primitives.BigInteger(1)
        b = primitives.BigInteger(2)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        BigInteger to a non-BigInteger object.
        """
        a = primitives.BigInteger()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two BigIntegers with the same values.
        """
        a = primitives.BigInteger(1)
        b = primitives.BigInteger(1)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing
        two BigIntegers.
        """
        a = primitives.BigInteger()
        b = primitives.BigInteger()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        BigIntegers with different values.
        """
        a = primitives.BigInteger(1)
        b = primitives.BigInteger(2)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        BigInteger to a non-BigInteger object.
        """
        a = primitives.BigInteger()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)
