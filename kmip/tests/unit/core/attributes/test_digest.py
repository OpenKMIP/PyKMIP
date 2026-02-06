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

from kmip.core.attributes import Digest
from kmip.core.attributes import DigestValue
from kmip.core.attributes import HashingAlgorithm

from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum

from kmip.core.objects import KeyFormatType
from kmip.core.utils import BytearrayStream

class TestDigest(TestCase):
    """
    A test suite for the Digest class.
    """

    def setUp(self):
        super(TestDigest, self).setUp()

        self.hashing_algorithm_a = HashingAlgorithm(
            HashingAlgorithmEnum.SHA_256)
        self.hashing_algorithm_b = HashingAlgorithm(
            HashingAlgorithmEnum.SHA_256)
        self.hashing_algorithm_c = HashingAlgorithm(
            HashingAlgorithmEnum.SHA_256)
        self.hashing_algorithm_d = HashingAlgorithm(
            HashingAlgorithmEnum.SHA_1)

        self.digest_value_a = DigestValue(b'')
        self.digest_value_b = DigestValue(
            b'\x6C\x06\x4F\xE0\x51\xAD\xD1\x1E\xDC\x07\x72\x7B\x59\x4E\xB4\x87'
            b'\x11\xDF\x84\x3E\x08\x44\x5B\xBA\x2C\xD7\x86\xBC\x16\xBC\x58'
            b'\xE8')
        self.digest_value_c = DigestValue(
            b'\x11\x11\x0A\x01\xED\x45\x89\xD9\x98\x7C\x9A\xD6\x03\x68\xE2\xB7'
            b'\x62\xF2\xB2\x0C\x00\x94\x6E\x19\x32\xC1\x60\x5A\x18\x17\x2F'
            b'\x55')

        self.key_format_type_a = KeyFormatType(KeyFormatTypeEnum.RAW)
        self.key_format_type_b = KeyFormatType(KeyFormatTypeEnum.RAW)
        self.key_format_type_c = KeyFormatType(KeyFormatTypeEnum.PKCS_1)

        # Encodings obtained from Section 18.1 and 18.2 of the KMIP 1.1 Test
        # Cases document.
        self.encoding_a = BytearrayStream((
            b'\x42\x00\x34\x01\x00\x00\x00\x28\x42\x00\x38\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x06\x00\x00\x00\x00\x42\x00\x35\x08\x00\x00\x00\x00'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00'
            b'\x00'))
        self.encoding_b = BytearrayStream((
            b'\x42\x00\x34\x01\x00\x00\x00\x48\x42\x00\x38\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x06\x00\x00\x00\x00\x42\x00\x35\x08\x00\x00\x00\x20'
            b'\x6C\x06\x4F\xE0\x51\xAD\xD1\x1E\xDC\x07\x72\x7B\x59\x4E\xB4\x87'
            b'\x11\xDF\x84\x3E\x08\x44\x5B\xBA\x2C\xD7\x86\xBC\x16\xBC\x58\xE8'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00'
            b'\x00'))
        self.encoding_c = BytearrayStream((
            b'\x42\x00\x34\x01\x00\x00\x00\x48\x42\x00\x38\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x06\x00\x00\x00\x00\x42\x00\x35\x08\x00\x00\x00\x20'
            b'\x11\x11\x0A\x01\xED\x45\x89\xD9\x98\x7C\x9A\xD6\x03\x68\xE2\xB7'
            b'\x62\xF2\xB2\x0C\x00\x94\x6E\x19\x32\xC1\x60\x5A\x18\x17\x2F\x55'
            b'\x42\x00\x42\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00'
            b'\x00'))

    def tearDown(self):
        super(TestDigest, self).tearDown()

    def test_init_with_none(self):
        """
        Test that a Digest object can be constructed with no specified values.
        """
        Digest()

    def test_init_with_args(self):
        """
        Test that a Digest object can be constructed with valid values.
        """
        Digest(hashing_algorithm=HashingAlgorithm(),
               digest_value=DigestValue(),
               key_format_type=KeyFormatType())

    def test_validate_with_invalid_hashing_algorithm(self):
        """
        Test that a TypeError exception is raised when an invalid
        HashingAlgorithm is used to construct a Digest object.
        """
        hashing_algorithm = "invalid"
        kwargs = {'hashing_algorithm': hashing_algorithm}

        self.assertRaisesRegex(
            TypeError, "invalid hashing algorithm", Digest, **kwargs)

    def test_validate_with_invalid_digest_value(self):
        """
        Test that a TypeError exception is raised when an invalid DigestValue
        is used to construct a Digest object.
        """
        digest_value = "invalid"
        kwargs = {'digest_value': digest_value}

        self.assertRaisesRegex(
            TypeError, "invalid digest value", Digest, **kwargs)

    def test_validate_with_invalid_key_format_type(self):
        """
        Test that a TypeError exception is raised when an invalid
        KeyFormatType is used to construct a Digeest object.
        """
        key_format_type = "invalid"
        kwargs = {'key_format_type': key_format_type}

        self.assertRaisesRegex(
            TypeError, "invalid key format type", Digest, **kwargs)

    def _test_read(self, stream, hashing_algorithm, digest_value,
                   key_format_type):
        digest = Digest()
        digest.read(stream)

        msg = "hashing algorithm encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            hashing_algorithm,
            digest.hashing_algorithm)
        self.assertEqual(
            hashing_algorithm,
            digest.hashing_algorithm, msg)

        msg = "digest value encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            digest_value,
            digest.digest_value)
        self.assertEqual(
            digest_value,
            digest.digest_value, msg)

        msg = "key format type encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            key_format_type,
            digest.key_format_type)
        self.assertEqual(
            key_format_type,
            digest.key_format_type, msg)

    def test_read_a(self):
        """
        Test that a Digest object with some data can be read from a data
        stream.
        """
        self._test_read(self.encoding_a, self.hashing_algorithm_a,
                        self.digest_value_a, self.key_format_type_a)

    def test_read_b(self):
        """
        Test that a Digest object with data can be read from a data stream.
        """
        self._test_read(self.encoding_b, self.hashing_algorithm_b,
                        self.digest_value_b, self.key_format_type_b)

    def test_read_c(self):
        """
        Test that a Digest object with data can be read from a data stream.
        """
        self._test_read(self.encoding_c, self.hashing_algorithm_c,
                        self.digest_value_c, self.key_format_type_c)

    def _test_write(self, stream_expected, hashing_algorithm, digest_value,
                    key_format_type):
        stream_observed = BytearrayStream()
        digest = Digest(
            hashing_algorithm=hashing_algorithm,
            digest_value=digest_value,
            key_format_type=key_format_type)
        digest.write(stream_observed)

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

    def test_write_a(self):
        """
        Test that a Digest object with some data can be written to a data
        stream.
        """
        self._test_write(self.encoding_a, self.hashing_algorithm_a,
                         self.digest_value_a, self.key_format_type_a)

    def test_write_b(self):
        """
        Test that a Digest object with data can be written to a data stream.
        """
        self._test_write(self.encoding_b, self.hashing_algorithm_b,
                         self.digest_value_b, self.key_format_type_b)

    def test_write_c(self):
        """
        Test that a Digest object with data can be written to a data stream.
        """
        self._test_write(self.encoding_c, self.hashing_algorithm_c,
                         self.digest_value_c, self.key_format_type_c)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Digest
        objects with the same internal data.
        """
        a = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)
        b = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two Digest
        objects with no internal data.
        """
        a = Digest()
        b = Digest()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        Digest objects with different sets of internal data.
        """
        a = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)
        b = Digest()

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a Digest
        object with a non-Digest object.
        """
        a = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Digest objects with the same internal data.
        """
        a = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)
        b = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing two
        Digest objects with no internal data.
        """
        a = Digest()
        b = Digest()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        Digest objects with the different sets of internal data.
        """
        a = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)
        b = Digest()
        c = Digest(
            hashing_algorithm=self.hashing_algorithm_d,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_c)
        d = Digest(
            key_format_type=self.key_format_type_c)

        self.assertTrue(a != b)
        self.assertTrue(b != a)
        self.assertTrue(b != c)
        self.assertTrue(b != d)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing an
        Digest object with a non-ExtensionInformation object.
        """
        a = Digest(
            hashing_algorithm=self.hashing_algorithm_b,
            digest_value=self.digest_value_b,
            key_format_type=self.key_format_type_b)
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that the representation of a Digest object with data is formatted
        properly.
        """
        hashing_algorithm = HashingAlgorithm(HashingAlgorithmEnum.MD5)
        digest_value = DigestValue(b'\x00\x01\x02\x03')
        key_format_type = KeyFormatType(KeyFormatTypeEnum.RAW)
        digest = Digest(
            hashing_algorithm=hashing_algorithm,
            digest_value=digest_value,
            key_format_type=key_format_type)

        hashing_algorithm = "hashing_algorithm={0}".format(
            repr(hashing_algorithm))
        digest_value = "digest_value={0}".format(repr(digest_value))
        key_format_type = "key_format_type={0}".format(repr(key_format_type))

        expected = "Digest({0}, {1}, {2})".format(
            hashing_algorithm, digest_value, key_format_type)
        observed = repr(digest)

        msg = "expected:\n{0},\nobserved:\n{1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def _test_str(self, value, expected):
        digest = Digest(digest_value=value)

        observed = str(digest)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_str_with_no_data(self):
        """
        Test that the string representation of a Digest object is formatted
        properly when there is no internal data.
        """
        data = b''
        digest_value = DigestValue(data)
        self._test_str(digest_value, str(data))

    def test_str_with_data(self):
        """
        Test that the string representation of a Digest object is formatted
        properly when there is internal data.
        """
        data = b'\x00\x01\x02\x03'
        digest_value = DigestValue(data)
        self._test_str(digest_value, str(data))

    def _test_create(self, digest, hashing_algorithm, digest_value,
                     key_format_type):
        self.assertIsInstance(digest, Digest)

        expected = HashingAlgorithm(hashing_algorithm)
        observed = digest.hashing_algorithm

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = DigestValue(digest_value)
        observed = digest.digest_value

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = KeyFormatType(key_format_type)
        observed = digest.key_format_type

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_create_with_defaults(self):
        """
        Test that a Digest object can be built using the create class method
        with no arguments.
        """
        digest = Digest.create()
        hashing_algorithm = HashingAlgorithmEnum.SHA_256
        digest_value = b''
        key_format_type = KeyFormatTypeEnum.RAW

        self._test_create(digest, hashing_algorithm, digest_value,
                          key_format_type)

    def test_create_with_args(self):
        """
        Test that a Digest object can be built using the create class method
        with arguments.
        """
        hashing_algorithm = HashingAlgorithmEnum.MD5
        digest_value = b'\x00\x01\x02\x03'
        key_format_type = KeyFormatTypeEnum.PKCS_1
        digest = Digest.create(hashing_algorithm, digest_value,
                               key_format_type)

        self._test_create(digest, hashing_algorithm, digest_value,
                          key_format_type)
