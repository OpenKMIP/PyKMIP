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

from kmip.core import utils

from kmip.core.messages.contents import ProtocolVersion
from kmip.core.messages import payloads

class TestDiscoverVersionsRequestPayload(TestCase):

    def setUp(self):
        super(TestDiscoverVersionsRequestPayload, self).setUp()

        self.protocol_versions_empty = list()
        self.protocol_versions_one = list()
        self.protocol_versions_one.append(ProtocolVersion(1, 0))
        self.protocol_versions_two = list()
        self.protocol_versions_two.append(ProtocolVersion(1, 1))
        self.protocol_versions_two.append(ProtocolVersion(1, 0))

        self.encoding_empty = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x00'))
        self.encoding_one = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x28\x42\x00\x69\x01\x00\x00\x00\x20'
            b'\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
            b'\x00'))
        self.encoding_two = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x50\x42\x00\x69\x01\x00\x00\x00\x20'
            b'\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestDiscoverVersionsRequestPayload, self).tearDown()

    def test_init_with_none(self):
        payloads.DiscoverVersionsRequestPayload()

    def test_init_with_args(self):
        payloads.DiscoverVersionsRequestPayload(
            self.protocol_versions_empty)

    def test_init(self):
        payloads.DiscoverVersionsRequestPayload()

    def test_validate_with_invalid_protocol_versions(self):
        kwargs = {'protocol_versions': 'invalid'}
        self.assertRaisesRegex(
            TypeError, "invalid protocol versions list",
            payloads.DiscoverVersionsRequestPayload, **kwargs)

    def test_validate_with_invalid_protocol_version(self):
        kwargs = {'protocol_versions': ['invalid']}
        self.assertRaisesRegex(
            TypeError, "invalid protocol version",
            payloads.DiscoverVersionsRequestPayload, **kwargs)

    def _test_read(self, stream, payload, protocol_versions):
        payload.read(stream)
        expected = len(protocol_versions)
        observed = len(payload.protocol_versions)

        msg = "protocol versions list decoding mismatch"
        msg += "; expected {0} results, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

        for i in range(len(protocol_versions)):
            expected = protocol_versions[i]
            observed = payload.protocol_versions[i]

            msg = "protocol version decoding mismatch"
            msg += "; expected {0}, received {1}".format(expected, observed)
            self.assertEqual(expected, observed, msg)

    def test_read_with_empty_protocol_list(self):
        stream = self.encoding_empty
        payload = payloads.DiscoverVersionsRequestPayload()
        protocol_versions = self.protocol_versions_empty

        self._test_read(stream, payload, protocol_versions)

    def test_read_with_one_protocol_version(self):
        stream = self.encoding_one
        payload = payloads.DiscoverVersionsRequestPayload()
        protocol_versions = self.protocol_versions_one

        self._test_read(stream, payload, protocol_versions)

    def test_read_with_two_protocol_versions(self):
        stream = self.encoding_two
        payload = payloads.DiscoverVersionsRequestPayload()
        protocol_versions = self.protocol_versions_two

        self._test_read(stream, payload, protocol_versions)

    def _test_write(self, payload, expected):
        stream = utils.BytearrayStream()
        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)

        self.assertEqual(expected, stream, msg)

    def test_write_with_empty_protocol_list(self):
        payload = payloads.DiscoverVersionsRequestPayload(
            self.protocol_versions_empty)
        expected = self.encoding_empty

        self._test_write(payload, expected)

    def test_write_with_one_protocol_version(self):
        payload = payloads.DiscoverVersionsRequestPayload(
            self.protocol_versions_one)
        expected = self.encoding_one

        self._test_write(payload, expected)

    def test_write_with_two_protocol_versions(self):
        payload = payloads.DiscoverVersionsRequestPayload(
            self.protocol_versions_two)
        expected = self.encoding_two

        self._test_write(payload, expected)

    def test_read_valid(self):
        payload = payloads.DiscoverVersionsRequestPayload()
        self._test_read(self.encoding_one, payload, self.protocol_versions_one)

    def test_read_missing_required_field(self):
        payload = payloads.DiscoverVersionsRequestPayload()
        self.assertRaises(
            Exception,
            payload.read,
            utils.BytearrayStream(b'')
        )

    def test_write_valid(self):
        payload = payloads.DiscoverVersionsRequestPayload(
            self.protocol_versions_one)
        self._test_write(payload, self.encoding_one)

    def test_read_write_roundtrip(self):
        payload = payloads.DiscoverVersionsRequestPayload()
        payload.read(utils.BytearrayStream(self.encoding_one.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.encoding_one, stream)

    def test_validate_invalid(self):
        self.test_validate_with_invalid_protocol_versions()

    def test_eq(self):
        payload = payloads.DiscoverVersionsRequestPayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        a = payloads.DiscoverVersionsRequestPayload(self.protocol_versions_one)
        b = payloads.DiscoverVersionsRequestPayload(self.protocol_versions_two)
        self.assertTrue(a != b)

    def test_repr(self):
        payload = payloads.DiscoverVersionsRequestPayload()
        self.assertIsInstance(repr(payload), str)

    def test_str(self):
        payload = payloads.DiscoverVersionsRequestPayload()
        self.assertIsInstance(str(payload), str)

class TestDiscoverVersionsResponsePayload(TestCase):

    def setUp(self):
        super(TestDiscoverVersionsResponsePayload, self).setUp()

        self.protocol_versions_empty = list()
        self.protocol_versions_one = list()
        self.protocol_versions_one.append(ProtocolVersion(1, 0))
        self.protocol_versions_two = list()
        self.protocol_versions_two.append(ProtocolVersion(1, 1))
        self.protocol_versions_two.append(ProtocolVersion(1, 0))

        self.encoding_empty = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'))
        self.encoding_one = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x28\x42\x00\x69\x01\x00\x00\x00\x20'
            b'\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
            b'\x00'))
        self.encoding_two = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x50\x42\x00\x69\x01\x00\x00\x00\x20'
            b'\x42\x00\x6A\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x6B\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x69\x01\x00\x00\x00\x20\x42\x00\x6A\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x6B\x02\x00\x00\x00\x04'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestDiscoverVersionsResponsePayload, self).tearDown()

    def test_init_with_none(self):
        payloads.DiscoverVersionsResponsePayload()

    def test_init_with_args(self):
        payloads.DiscoverVersionsResponsePayload(
            self.protocol_versions_empty)

    def test_init(self):
        payloads.DiscoverVersionsResponsePayload()

    def test_validate_with_invalid_protocol_versions(self):
        kwargs = {'protocol_versions': 'invalid'}
        self.assertRaisesRegex(
            TypeError, "invalid protocol versions list",
            payloads.DiscoverVersionsResponsePayload, **kwargs)

    def test_validate_with_invalid_protocol_version(self):
        kwargs = {'protocol_versions': ['invalid']}
        self.assertRaisesRegex(
            TypeError, "invalid protocol version",
            payloads.DiscoverVersionsResponsePayload, **kwargs)

    def _test_read(self, stream, payload, protocol_versions):
        payload.read(stream)
        expected = len(protocol_versions)
        observed = len(payload.protocol_versions)

        msg = "protocol versions list decoding mismatch"
        msg += "; expected {0} results, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

        for i in range(len(protocol_versions)):
            expected = protocol_versions[i]
            observed = payload.protocol_versions[i]

            msg = "protocol version decoding mismatch"
            msg += "; expected {0}, received {1}".format(expected, observed)
            self.assertEqual(expected, observed, msg)

    def test_read_with_empty_protocol_list(self):
        stream = self.encoding_empty
        payload = payloads.DiscoverVersionsResponsePayload()
        protocol_versions = self.protocol_versions_empty

        self._test_read(stream, payload, protocol_versions)

    def test_read_with_one_protocol_version(self):
        stream = self.encoding_one
        payload = payloads.DiscoverVersionsResponsePayload()
        protocol_versions = self.protocol_versions_one

        self._test_read(stream, payload, protocol_versions)

    def test_read_with_two_protocol_versions(self):
        stream = self.encoding_two
        payload = payloads.DiscoverVersionsResponsePayload()
        protocol_versions = self.protocol_versions_two

        self._test_read(stream, payload, protocol_versions)

    def _test_write(self, payload, expected):
        stream = utils.BytearrayStream()
        payload.write(stream)

        length_expected = len(expected)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(expected, stream)

        self.assertEqual(expected, stream, msg)

    def test_write_with_empty_protocol_list(self):
        payload = payloads.DiscoverVersionsResponsePayload(
            self.protocol_versions_empty)
        expected = self.encoding_empty

        self._test_write(payload, expected)

    def test_write_with_one_protocol_version(self):
        payload = payloads.DiscoverVersionsResponsePayload(
            self.protocol_versions_one)
        expected = self.encoding_one

        self._test_write(payload, expected)

    def test_write_with_two_protocol_versions(self):
        payload = payloads.DiscoverVersionsResponsePayload(
            self.protocol_versions_two)
        expected = self.encoding_two

        self._test_write(payload, expected)

    def test_read_valid(self):
        payload = payloads.DiscoverVersionsResponsePayload()
        self._test_read(self.encoding_one, payload, self.protocol_versions_one)

    def test_read_missing_required_field(self):
        payload = payloads.DiscoverVersionsResponsePayload()
        self.assertRaises(
            Exception,
            payload.read,
            utils.BytearrayStream(b'')
        )

    def test_write_valid(self):
        payload = payloads.DiscoverVersionsResponsePayload(
            self.protocol_versions_one)
        self._test_write(payload, self.encoding_one)

    def test_read_write_roundtrip(self):
        payload = payloads.DiscoverVersionsResponsePayload()
        payload.read(utils.BytearrayStream(self.encoding_one.buffer))

        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(self.encoding_one, stream)

    def test_validate_invalid(self):
        self.test_validate_with_invalid_protocol_versions()

    def test_eq(self):
        payload = payloads.DiscoverVersionsResponsePayload()
        self.assertTrue(payload == payload)

    def test_ne(self):
        a = payloads.DiscoverVersionsResponsePayload(self.protocol_versions_one)
        b = payloads.DiscoverVersionsResponsePayload(self.protocol_versions_two)
        self.assertTrue(a != b)

    def test_repr(self):
        payload = payloads.DiscoverVersionsResponsePayload()
        self.assertIsInstance(repr(payload), str)

    def test_str(self):
        payload = payloads.DiscoverVersionsResponsePayload()
        self.assertIsInstance(str(payload), str)
