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

from kmip.core import attributes
from kmip.core import misc
from kmip.core import objects
from kmip.core import utils

from kmip.core.messages import payloads

class TestRekeyKeyPairRequestPayload(TestCase):

    def setUp(self):
        super(TestRekeyKeyPairRequestPayload, self).setUp()

        self.uuid = '00000000-0000-0000-0000-000000000000'
        self.private_key_uuid = attributes.PrivateKeyUniqueIdentifier(
            self.uuid)
        self.offset = misc.Offset(0)
        self.common_template_attribute = objects.CommonTemplateAttribute()
        self.private_key_template_attribute = \
            objects.PrivateKeyTemplateAttribute()
        self.public_key_template_attribute = \
            objects.PublicKeyTemplateAttribute()

        self.encoding_empty = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x00'))
        self.encoding_full = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x58\x42\x00\x66\x07\x00\x00\x00\x24'
            b'\x30\x30\x30\x30\x30\x30\x30\x30\x2d\x30\x30\x30\x30\x2d\x30\x30'
            b'\x30\x30\x2d\x30\x30\x30\x30\x2d\x30\x30\x30\x30\x30\x30\x30\x30'
            b'\x30\x30\x30\x30\x00\x00\x00\x00\x42\x00\x58\x0A\x00\x00\x00\x04'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x42\x00\x1F\x01\x00\x00\x00\x00'
            b'\x42\x00\x65\x01\x00\x00\x00\x00\x42\x00\x6E\x01\x00\x00\x00\x00'
            ))

    def tearDown(self):
        super(TestRekeyKeyPairRequestPayload, self).tearDown()

    def test_init_with_none(self):
        payloads.RekeyKeyPairRequestPayload()

    def test_init_with_args(self):
        payloads.RekeyKeyPairRequestPayload(
            self.private_key_uuid, self.offset, self.common_template_attribute,
            self.private_key_template_attribute,
            self.public_key_template_attribute)

    def test_validate_with_invalid_private_key_unique_identifier(self):
        kwargs = {'private_key_uuid': 'invalid', 'offset': None,
                  'common_template_attribute': None,
                  'private_key_template_attribute': None,
                  'public_key_template_attribute': None}
        self.assertRaisesRegex(
            TypeError, "invalid private key unique identifier",
            payloads.RekeyKeyPairRequestPayload, **kwargs)

    def test_validate_with_invalid_offset(self):
        kwargs = {'private_key_uuid': None, 'offset': 'invalid',
                  'common_template_attribute': None,
                  'private_key_template_attribute': None,
                  'public_key_template_attribute': None}
        self.assertRaisesRegex(
            TypeError, "invalid offset",
            payloads.RekeyKeyPairRequestPayload, **kwargs)

    def test_validate_with_invalid_common_template_attribute(self):
        kwargs = {'private_key_uuid': None, 'offset': None,
                  'common_template_attribute': 'invalid',
                  'private_key_template_attribute': None,
                  'public_key_template_attribute': None}
        self.assertRaisesRegex(
            TypeError, "invalid common template attribute",
            payloads.RekeyKeyPairRequestPayload, **kwargs)

    def test_validate_with_invalid_private_key_template_attribute(self):
        kwargs = {'private_key_uuid': None, 'offset': None,
                  'common_template_attribute': None,
                  'private_key_template_attribute': 'invalid',
                  'public_key_template_attribute': None}
        self.assertRaisesRegex(
            TypeError, "invalid private key template attribute",
            payloads.RekeyKeyPairRequestPayload, **kwargs)

    def test_validate_with_invalid_public_key_template_attribute(self):
        kwargs = {'private_key_uuid': None, 'offset': None,
                  'common_template_attribute': None,
                  'private_key_template_attribute': None,
                  'public_key_template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError, "invalid public key template attribute",
            payloads.RekeyKeyPairRequestPayload, **kwargs)

    def _test_read(self, stream, payload, private_key_uuid, offset,
                   common_template_attribute, private_key_template_attribute,
                   public_key_template_attribute):
        payload.read(stream)

        msg = "private_key_uuid decoding mismatch"
        msg += "; expected {0}, received {1}".format(
            private_key_uuid, payload.private_key_uuid)
        self.assertEqual(private_key_uuid, payload.private_key_uuid, msg)

        msg = "offset decoding mismatch"
        msg += "; expected {0}, received {1}".format(offset, payload.offset)
        self.assertEqual(offset, payload.offset, msg)

        msg = "common_template_attribute decoding mismatch"
        msg += "; expected {0}, received {1}".format(
            common_template_attribute, payload.common_template_attribute)
        self.assertEqual(common_template_attribute,
                         payload.common_template_attribute, msg)

        msg = "private_key_template_attribute decoding mismatch"
        msg += "; expected {0}, received {1}".format(
            private_key_template_attribute,
            payload.private_key_template_attribute)
        self.assertEqual(private_key_template_attribute,
                         payload.private_key_template_attribute, msg)

        msg = "public_key_template_attribute decoding mismatch"
        msg += "; expected {0}, received {1}".format(
            public_key_template_attribute,
            payload.public_key_template_attribute)
        self.assertEqual(public_key_template_attribute,
                         payload.public_key_template_attribute, msg)

    def test_read_with_none(self):
        stream = self.encoding_empty
        payload = payloads.RekeyKeyPairRequestPayload()

        self._test_read(stream, payload, None, None, None, None, None)

    def test_read_with_args(self):
        stream = self.encoding_full
        payload = payloads.RekeyKeyPairRequestPayload()

        self._test_read(stream, payload, self.private_key_uuid, self.offset,
                        self.common_template_attribute,
                        self.private_key_template_attribute,
                        self.public_key_template_attribute)

    def _test_write(self, stream, payload, expected):
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

    def test_write_with_none(self):
        stream = utils.BytearrayStream()
        payload = payloads.RekeyKeyPairRequestPayload()

        self._test_write(stream, payload, self.encoding_empty)

    def test_write_with_args(self):
        stream = utils.BytearrayStream()
        payload = payloads.RekeyKeyPairRequestPayload(
            self.private_key_uuid, self.offset, self.common_template_attribute,
            self.private_key_template_attribute,
            self.public_key_template_attribute)

        self._test_write(stream, payload, self.encoding_full)

# TODO (ph) Replicate CreateKeyPairResponsePayload test suite here
class TestRekeyKeyPairResponsePayload(TestCase):

    def setUp(self):
        super(TestRekeyKeyPairResponsePayload, self).setUp()

        self.encoding_empty = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x10\x42\x00\x66\x07\x00\x00\x00\x00'
            b'\x42\x00\x6F\x07\x00\x00\x00\x00'))
        self.encoding_full = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x70\x42\x00\x66\x07\x00\x00\x00\x24'
            b'\x30\x30\x30\x30\x30\x30\x30\x30\x2d\x30\x30\x30\x30\x2d\x30\x30'
            b'\x30\x30\x2d\x30\x30\x30\x30\x2d\x30\x30\x30\x30\x30\x30\x30\x30'
            b'\x30\x30\x30\x30\x00\x00\x00\x00\x42\x00\x6F\x07\x00\x00\x00\x24'
            b'\x30\x30\x30\x30\x30\x30\x30\x30\x2d\x30\x30\x30\x30\x2d\x30\x30'
            b'\x30\x30\x2d\x30\x30\x30\x30\x2d\x30\x30\x30\x30\x30\x30\x30\x30'
            b'\x30\x30\x30\x30\x00\x00\x00\x00\x42\x00\x65\x01\x00\x00\x00\x00'
            b'\x42\x00\x6E\x01\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestRekeyKeyPairResponsePayload, self).tearDown()
