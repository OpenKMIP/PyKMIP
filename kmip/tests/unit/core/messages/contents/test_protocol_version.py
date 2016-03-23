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

from kmip.core.messages.contents import ProtocolVersion
from kmip.core.utils import BytearrayStream


class TestProtocolVersion(TestCase):

    def setUp(self):
        super(TestProtocolVersion, self).setUp()

        self.major_default = ProtocolVersion.ProtocolVersionMajor()
        self.minor_default = ProtocolVersion.ProtocolVersionMinor()
        self.major = ProtocolVersion.ProtocolVersionMajor(1)
        self.minor = ProtocolVersion.ProtocolVersionMinor(1)

        self.encoding_default = BytearrayStream((
            b'\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'))
        self.encoding = BytearrayStream((
            b'\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestProtocolVersion, self).tearDown()

    def _test_init(self, protocol_version_major, protocol_version_minor):
        protocol_version = ProtocolVersion(
            protocol_version_major, protocol_version_minor)

        if protocol_version_major is None:
            self.assertEqual(ProtocolVersion.ProtocolVersionMajor(),
                             protocol_version.protocol_version_major)
        else:
            self.assertEqual(protocol_version_major,
                             protocol_version.protocol_version_major)

        if protocol_version_minor is None:
            self.assertEqual(ProtocolVersion.ProtocolVersionMinor(),
                             protocol_version.protocol_version_minor)
        else:
            self.assertEqual(protocol_version_minor,
                             protocol_version.protocol_version_minor)

    def test_init_with_none(self):
        self._test_init(None, None)

    def test_init_with_args(self):
        major = ProtocolVersion.ProtocolVersionMajor(1)
        minor = ProtocolVersion.ProtocolVersionMinor(0)

        self._test_init(major, minor)

    def test_validate_on_invalid_protocol_version_major(self):
        major = "invalid"
        minor = ProtocolVersion.ProtocolVersionMinor(0)
        args = [major, minor]

        self.assertRaisesRegexp(
            TypeError, "invalid protocol version major", self._test_init,
            *args)

    def test_validate_on_invalid_protocol_version_minor(self):
        major = ProtocolVersion.ProtocolVersionMajor(1)
        minor = "invalid"
        args = [major, minor]

        self.assertRaisesRegexp(
            TypeError, "invalid protocol version minor", self._test_init,
            *args)

    def _test_read(self, stream, major, minor):
        protocol_version = ProtocolVersion()
        protocol_version.read(stream)

        msg = "protocol version major decoding mismatch"
        msg += "; expected {0}, received {1}".format(
            major, protocol_version.protocol_version_major)
        self.assertEqual(major, protocol_version.protocol_version_major, msg)

        msg = "protocol version minor decoding mismatch"
        msg += "; expected {0}, received {1}".format(
            minor, protocol_version.protocol_version_minor)
        self.assertEqual(minor, protocol_version.protocol_version_minor, msg)

    def test_read_with_none(self):
        self._test_read(self.encoding_default, self.major_default,
                        self.minor_default)

    def test_read_with_args(self):
        self._test_read(self.encoding, self.major, self.minor)

    def _test_write(self, stream_expected, major, minor):
        stream_observed = BytearrayStream()
        protocol_version = ProtocolVersion(major, minor)
        protocol_version.write(stream_observed)

        length_expected = len(stream_expected)
        length_observed = len(stream_observed)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_observed)
        self.assertEqual(length_expected, length_observed, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(
            stream_expected, stream_observed)

        self.assertEqual(stream_expected, stream_observed, msg)

    def test_write_with_none(self):
        self._test_write(self.encoding_default, self.major_default,
                         self.minor_default)

    def test_write_with_args(self):
        self._test_write(self.encoding, self.major, self.minor)

    def test_equal_on_equal(self):
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(1, 0)

        self.assertTrue(a == b)

    def test_equal_on_not_equal(self):
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(0, 1)

        self.assertFalse(a == b)

    def test_equal_on_type_mismatch(self):
        a = ProtocolVersion.create(1, 0)
        b = "invalid"

        self.assertFalse(a == b)

    def test_not_equal_on_equal(self):
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(1, 0)

        self.assertFalse(a != b)

    def test_not_equal_on_not_equal(self):
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(0, 1)

        self.assertTrue(a != b)

    def test_not_equal_on_type_mismatch(self):
        a = ProtocolVersion.create(1, 0)
        b = "invalid"

        self.assertTrue(a != b)

    def test_less_than(self):
        """
        Test that the less than operator returns True/False when comparing
        two different ProtocolVersions.
        """
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(1, 1)
        c = ProtocolVersion.create(2, 0)
        d = ProtocolVersion.create(0, 2)

        self.assertTrue(a < b)
        self.assertFalse(b < a)
        self.assertFalse(a < a)
        self.assertTrue(a < c)
        self.assertFalse(c < a)
        self.assertFalse(c < d)
        self.assertTrue(d < c)

    def test_greater_than(self):
        """
        Test that the greater than operator returns True/False when
        comparing two different ProtocolVersions.
        """
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(1, 1)
        c = ProtocolVersion.create(2, 0)
        d = ProtocolVersion.create(0, 2)

        self.assertFalse(a > b)
        self.assertTrue(b > a)
        self.assertFalse(a > a)
        self.assertFalse(a > c)
        self.assertTrue(c > a)
        self.assertTrue(c > d)
        self.assertFalse(d > c)

    def test_less_than_or_equal(self):
        """
        Test that the less than or equal operator returns True/False when
        comparing two different ProtocolVersions.
        """
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(1, 1)
        c = ProtocolVersion.create(2, 0)
        d = ProtocolVersion.create(0, 2)

        self.assertTrue(a <= b)
        self.assertFalse(b <= a)
        self.assertTrue(a <= a)
        self.assertTrue(a <= c)
        self.assertFalse(c <= a)
        self.assertFalse(c <= d)
        self.assertTrue(d <= c)

    def test_greater_than_or_equal(self):
        """
        Test that the greater than or equal operator returns True/False when
        comparing two different ProtocolVersions.
        """
        a = ProtocolVersion.create(1, 0)
        b = ProtocolVersion.create(1, 1)
        c = ProtocolVersion.create(2, 0)
        d = ProtocolVersion.create(0, 2)

        self.assertFalse(a >= b)
        self.assertTrue(b >= a)
        self.assertTrue(a >= a)
        self.assertFalse(a >= c)
        self.assertTrue(c >= a)
        self.assertTrue(c >= d)
        self.assertFalse(d >= c)

    def test_repr(self):
        a = ProtocolVersion.create(1, 0)

        self.assertEqual("1.0", "{0}".format(a))

    def _test_create(self, major, minor):
        protocol_version = ProtocolVersion.create(major, minor)

        if major is None:
            expected = ProtocolVersion.ProtocolVersionMajor()
        else:
            expected = ProtocolVersion.ProtocolVersionMajor(major)

        self.assertEqual(expected, protocol_version.protocol_version_major)

        if minor is None:
            expected = ProtocolVersion.ProtocolVersionMinor()
        else:
            expected = ProtocolVersion.ProtocolVersionMinor(minor)

        self.assertEqual(expected, protocol_version.protocol_version_minor)

    def test_create_with_none(self):
        self._test_create(None, None)

    def test_create_with_args(self):
        self._test_create(1, 0)
