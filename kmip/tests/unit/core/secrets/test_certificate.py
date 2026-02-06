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

from kmip.core.attributes import CertificateType
from kmip.core import enums
from kmip.core.misc import CertificateValue
from kmip.core.secrets import Certificate
from kmip.core.utils import BytearrayStream

class TestCertificate(TestCase):
    """
    A test suite for the Certificate class.
    """

    def setUp(self):
        super(TestCertificate, self).setUp()

        self.certificate_type_a = None
        self.certificate_type_b = enums.CertificateType.X_509

        # Encodings obtained from Section 13.2 of KMIP 1.1 Test Cases document.
        self.certificate_value_a = None
        self.certificate_value_b = (
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86')

        self.encoding_a = BytearrayStream((
            b'\x42\x00\x13\x01\x00\x00\x00\x18\x42\x00\x1D\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x1E\x08\x00\x00\x00'
            b'\x00'))
        self.encoding_b = BytearrayStream((
            b'\x42\x00\x13\x01\x00\x00\x03\x30\x42\x00\x1D\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x1E\x08\x00\x00\x03\x16'
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86\x00\x00'))

    def tearDown(self):
        super(TestCertificate, self).tearDown()

    def test_init(self):
        pass

    def _test_read(self, stream, certificate_type, certificate_value):
        certificate = Certificate()
        certificate.read(stream)

        if certificate_type is None:
            expected = CertificateType()
        else:
            expected = CertificateType(certificate_type)

        observed = certificate.certificate_type

        msg = "certificate type encoding mismatch; "
        msg += "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed)

        if certificate_value is None:
            expected = CertificateValue()
        else:
            expected = CertificateValue(certificate_value)

        observed = certificate.certificate_value

        msg = "certificate value encoding mismatch; "
        msg += "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_read_a(self):
        """
        Test that a Certificate object with no data can be read from a data
        stream.
        """
        self._test_read(self.encoding_a, self.certificate_type_a,
                        self.certificate_value_a)

    def test_read_b(self):
        """
        Test that a Certificate object with data can be read from a data
        stream.
        """
        self._test_read(self.encoding_b, self.certificate_type_b,
                        self.certificate_value_b)

    def _test_write(self, stream, certificate_type, certificate_value):
        certificate = Certificate(
            certificate_type=certificate_type,
            certificate_value=certificate_value)

        expected = stream
        observed = BytearrayStream()

        certificate.write(observed)

        msg = "encoding mismatch;\nexpected:\n{0}\nobserved:\n{1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_write_a(self):
        """
        Test that a Certificate object with no data can be written to a data
        stream.
        """
        self._test_write(self.encoding_a, self.certificate_type_a,
                         self.certificate_value_a)

    def test_write_b(self):
        """
        Test that a Certificate object with data can be written to a data
        stream.
        """
        self._test_write(self.encoding_b, self.certificate_type_b,
                         self.certificate_value_b)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Certificate objects with the same internal data.
        """
        a = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)
        b = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        Certificate objects with no internal data.
        """
        a = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)
        b = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        Certificate objects with different sets of internal data.
        """
        a = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)
        b = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        Certificate object with a non-Certificate object.
        """
        a = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Certificate objects with the same internal data.
        """
        a = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)
        b = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing two
        Certificate objects with no internal data.
        """
        a = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)
        b = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        Certificate objects with different sets of internal data.
        """
        a = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)
        b = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        Certificate object with a non-Certificate object.
        """
        a = Certificate(
            certificate_type=self.certificate_type_a,
            certificate_value=self.certificate_value_a)
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that the representation of a Certificate object with data is
        formatted properly.
        """
        certificate = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)

        certificate_type = "certificate_type={0}".format(
            str(self.certificate_type_b))
        certificate_value = "certificate_value=b'{0}'".format(
            str(self.certificate_value_b))

        expected = "Certificate({0}, {1})".format(
            certificate_type, certificate_value)
        observed = repr(certificate)

        msg = "\nexpected:\n{0}\nobserved:\n{1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        # NOTE (peter-hamilton) Testing with eval won't work due to null bytes.

    def test_str(self):
        """
        Test that the string representation of a Certificate object is
        formatted properly.
        """
        certificate = Certificate(
            certificate_type=self.certificate_type_b,
            certificate_value=self.certificate_value_b)

        expected = str(self.certificate_value_b)
        observed = str(certificate)

        msg = "expected:\n{0}\nobserved:\n{1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)
