# Copyright (c) 2017 Pure Storage, Inc. All Rights Reserved.
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
from kmip.core import objects
from kmip.core import utils
from kmip.core import enums
from kmip.core import exceptions

from kmip.core.messages import payloads


class TestMACRequestPayload(TestCase):

    def setUp(self):
        super(TestMACRequestPayload, self).setUp()

        self.unique_identifier = attributes.UniqueIdentifier(value='1')
        self.cryptographic_parameters = \
            attributes.CryptographicParameters(
                cryptographic_algorithm=enums.CryptographicAlgorithm.
                HMAC_SHA512
            )
        self.data = objects.Data(
            value=(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B'
                   b'\x0C\x0D\x0E\x0F')
        )

        self.encoding_full = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x40\x42\x00\x94\x07\x00\x00\x00\x01'
            b'\x31\x00\x00\x00\x00\x00\x00\x00\x42\x00\x2b\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x0b\x00\x00\x00\x00'
            b'\x42\x00\xc2\x08\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'))
        self.encoding_no_data = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x28\x42\x00\x94\x07\x00\x00\x00\x01'
            b'\x31\x00\x00\x00\x00\x00\x00\x00\x42\x00\x2b\x01\x00\x00\x00\x10'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x0b\x00\x00\x00\x00'
        ))

    def tearDown(self):
        super(TestMACRequestPayload, self).tearDown()

    def test_init_with_none(self):
        payloads.MACRequestPayload()

    def test_init_valid(self):
        """
        Test that the payload can be properly constructed and the attributes
        cab be properly set and retrieved.
        """
        payload = payloads.MACRequestPayload(
            self.unique_identifier,
            self.cryptographic_parameters,
            self.data)
        self.assertEqual(payload.unique_identifier, self.unique_identifier)
        self.assertEqual(payload.cryptographic_parameters,
                         self.cryptographic_parameters)
        self.assertEqual(payload.data, self.data)

    def test_init_with_invalid_unique_identifier(self):
        kwargs = {'unique_identifier': 'invalid',
                  'cryptographic_parameters': None,
                  'data': None}
        self.assertRaisesRegexp(
            TypeError, "unique identifier must be UniqueIdentifier type",
            payloads.MACRequestPayload, **kwargs)

    def test_init_with_invalid_cryptographic_parameters(self):
        kwargs = {'unique_identifier': None,
                  'cryptographic_parameters': 'invalid',
                  'data': None}
        self.assertRaisesRegexp(
            TypeError,
            "cryptographic parameters must be CryptographicParameters type",
            payloads.MACRequestPayload, **kwargs)

    def test_init_with_invalid_data(self):
        kwargs = {'unique_identifier': None,
                  'cryptographic_parameters': None,
                  'data': 'invalid'}
        self.assertRaises(
            TypeError, "data must be Data type",
            payloads.MACRequestPayload, **kwargs)

    def test_read_valid(self):
        stream = self.encoding_full
        payload = payloads.MACRequestPayload()
        payload.read(stream)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(self.cryptographic_parameters,
                         payload.cryptographic_parameters)
        self.assertEqual(self.data, payload.data)

    def test_read_no_data(self):
        """
        Test that an InvalidKmipEncoding error gets raised when attempting to
        read a mac request encoding with no data.
        """
        payload = payloads.MACRequestPayload()
        args = (self.encoding_no_data,)
        self.assertRaisesRegexp(
            exceptions.InvalidKmipEncoding,
            "expected mac request data not found",
            payload.read,
            *args
        )

    def test_write_valid(self):
        expected = self.encoding_full

        stream = utils.BytearrayStream()
        payload = payloads.MACRequestPayload(
            self.unique_identifier,
            self.cryptographic_parameters,
            self.data)
        payload.write(stream)

        self.assertEqual(expected, stream)

    def test_write_with_no_data(self):
        """
        Test that an InvalidField error gets raised when attempting to
        write a mac request with no data.
        """
        stream = utils.BytearrayStream()
        payload = payloads.MACRequestPayload(
            self.unique_identifier,
            self.cryptographic_parameters,
            None)
        args = (stream,)
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The mac request data is required",
            payload.write,
            *args
        )


class TestMACResponsePayload(TestCase):

    def setUp(self):
        super(TestMACResponsePayload, self).setUp()

        self.unique_identifier = attributes.UniqueIdentifier(value='1')
        self.mac_data = objects.MACData(value=(
            b'\x99\x8b\x55\x59\x90\x9b\x85\x87\x5b\x90\x63\x13\x12\xbb\x32\x9f'
            b'\x6a\xc4\xed\x97\x6e\xac\x99\xe5\x21\x53\xc4\x19\x28\xf2\x2a\x5b'
            b'\xef\x79\xa4\xbe\x05\x3b\x31\x49\x19\xe0\x75\x23\xb9\xbe\xc8\x23'
            b'\x35\x60\x7e\x49\xba\xa9\x7e\xe0\x9e\x6b\x3d\x55\xf4\x51\xff\x7c'
            )
        )

        self.encoding_full = utils.BytearrayStream((
            b'\x42\x00\x7c\x01\x00\x00\x00\x58\x42\x00\x94\x07\x00\x00\x00\x01'
            b'\x31\x00\x00\x00\x00\x00\x00\x00\x42\x00\xc6\x08\x00\x00\x00\x40'
            b'\x99\x8b\x55\x59\x90\x9b\x85\x87\x5b\x90\x63\x13\x12\xbb\x32\x9f'
            b'\x6a\xc4\xed\x97\x6e\xac\x99\xe5\x21\x53\xc4\x19\x28\xf2\x2a\x5b'
            b'\xef\x79\xa4\xbe\x05\x3b\x31\x49\x19\xe0\x75\x23\xb9\xbe\xc8\x23'
            b'\x35\x60\x7e\x49\xba\xa9\x7e\xe0\x9e\x6b\x3d\x55\xf4\x51\xff\x7c'
        ))
        self.encoding_no_unique_identifier = utils.BytearrayStream((
            b'\x42\x00\x7c\x01\x00\x00\x00\x48\x42\x00\xc6\x08\x00\x00\x00\x40'
            b'\x99\x8b\x55\x59\x90\x9b\x85\x87\x5b\x90\x63\x13\x12\xbb\x32\x9f'
            b'\x6a\xc4\xed\x97\x6e\xac\x99\xe5\x21\x53\xc4\x19\x28\xf2\x2a\x5b'
            b'\xef\x79\xa4\xbe\x05\x3b\x31\x49\x19\xe0\x75\x23\xb9\xbe\xc8\x23'
            b'\x35\x60\x7e\x49\xba\xa9\x7e\xe0\x9e\x6b\x3d\x55\xf4\x51\xff\x7c'
        ))
        self.encoding_no_mac_data = utils.BytearrayStream((
            b'\x42\x00\x7c\x01\x00\x00\x00\x10\x42\x00\x94\x07\x00\x00\x00\x01'
            b'\x31\x00\x00\x00\x00\x00\x00\x00'
        ))

    def tearDown(self):
        super(TestMACResponsePayload, self).tearDown()

    def test_init_with_none(self):
        payloads.MACResponsePayload()

    def test_init_valid(self):
        """
        Test that the payload can be properly constructed and the attributes
        can be properly set and retrieved.
        """
        payload = payloads.MACResponsePayload(
            self.unique_identifier,
            self.mac_data)
        self.assertEqual(payload.unique_identifier, self.unique_identifier)
        self.assertEqual(payload.mac_data, self.mac_data)

    def test_init_with_invalid_unique_identifier(self):
        kwargs = {'unique_identifier': 'invalid',
                  'mac_data': None}
        self.assertRaisesRegexp(
            TypeError, "unique identifier must be UniqueIdentifier type",
            payloads.MACResponsePayload, **kwargs)

    def test_init_with_invalid_mac_data(self):
        kwargs = {'unique_identifier': None,
                  'mac_data': 'invalid'}
        self.assertRaises(
            TypeError, "data must be MACData type",
            payloads.MACResponsePayload, **kwargs)

    def test_read_valid(self):
        stream = self.encoding_full
        payload = payloads.MACResponsePayload()
        payload.read(stream)

        self.assertEqual(self.unique_identifier, payload.unique_identifier)
        self.assertEqual(self.mac_data, payload.mac_data)

    def test_read_no_unique_identifier(self):
        """
        Test that an InvalidKmipEncoding error gets raised when attempting to
        read a mac response encoding with no unique identifier.
        """
        payload = payloads.MACResponsePayload()
        args = (self.encoding_no_unique_identifier,)
        self.assertRaisesRegexp(
            exceptions.InvalidKmipEncoding,
            "expected mac response unique identifier not found",
            payload.read,
            *args
        )

    def test_read_no_mac_data(self):
        """
        Test that an InvalidKmipEncoding error gets raised when attempting to
        read a mac response encoding with no mac data.
        """
        payload = payloads.MACResponsePayload()
        args = (self.encoding_no_mac_data,)
        self.assertRaisesRegexp(
            exceptions.InvalidKmipEncoding,
            "expected mac response mac data not found",
            payload.read,
            *args
        )

    def test_write_valid(self):
        expected = self.encoding_full

        stream = utils.BytearrayStream()
        payload = payloads.MACResponsePayload(
            self.unique_identifier,
            self.mac_data)
        payload.write(stream)

        self.assertEqual(expected, stream)

    def test_write_with_no_unique_identifier(self):
        """
        Test that an InvalidField error gets raised when attempting to
        write a mac response with no unique identifier.
        """
        stream = utils.BytearrayStream()
        payload = payloads.MACResponsePayload(
            None,
            self.mac_data)
        args = (stream,)
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The mac response unique identifier is required",
            payload.write,
            *args
        )

    def test_write_with_no_data(self):
        """
        Test that an InvalidField error gets raised when attempting to
        write a mac response with no mac data.
        """
        stream = utils.BytearrayStream()
        payload = payloads.MACResponsePayload(
            self.unique_identifier,
            None)
        args = (stream,)
        self.assertRaisesRegexp(
            exceptions.InvalidField,
            "The mac response mac data is required",
            payload.write,
            *args
        )
