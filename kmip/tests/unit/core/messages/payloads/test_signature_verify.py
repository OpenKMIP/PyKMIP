# Copyright (c) 2017 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import utils

from kmip.core.messages.payloads import signature_verify

class TestSignatureVerifyRequestPayload(testtools.TestCase):
    """
    Test suite for the SignatureVerify request payload.
    """

    def setUp(self):
        super(TestSignatureVerifyRequestPayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Sections 3.1.3 and 14.1. The rest of the encoding was built by
        # hand.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 49a1ca88-6bea-4fb2-b450-7e58802c3038
        #     Cryptographic Parameters
        #         Digital Signature Algorithm - SHA 256 with RSA
        #     Data
        #         0xCDC87DA223D786DF3B45E0BBBC721326D1EE2AF806CC315475CC6F0D9C
        #         66E1B62371D45CE2392E1AC92844C310102F156A0D8D52C1F4C40BA3AA65
        #         095786CB769757A6563BA958FED0BCC984E8B517A3D5F515B23B8A41E74A
        #         A867693F90DFB061A6E86DFAAEE64472C00E5F20945729CBEBE77F06CE78
        #         E08F4098FBA41F9D6193C0317E8B60D4B6084ACB42D29E3808A3BC372D85
        #         E331170FCBF7CC72D0B71C296648B3A4D10F416295D0807AA625CAB2744F
        #         D9EA8FD223C42537029828BD16BE02546F130FD2E33B936D2676E08AED1B
        #         73318B750A0167D0
        #     Digested Data
        #         0x01020304050607080910111213141516
        #     Signature Data
        #         0x6BC3A06656842930A247E30D5864B4D819236BA7C68965862AD7DBC4E2
        #         4AF28E86BB531F03358BE5FB74777C6086F850CAEF893F0D6FCC2D0C91EC
        #         013693B4EA00B80CD49AAC4ECB5F8911AFE539ADA4A8F3823D1D13E472D1
        #         490547C659C7617F3D24087DDB6F2B72096167FC097CAB18E9A458FCB634
        #         CDCE8EE35894C484D7
        #     Correlation Value - 1
        #     Init Indicator - True
        #     Final Indicator - False

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x02\x00'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\xAE\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xC2\x08\x00\x00\x00\xD9'
            b'\xCD\xC8\x7D\xA2\x23\xD7\x86\xDF\x3B\x45\xE0\xBB\xBC\x72\x13\x26'
            b'\xD1\xEE\x2A\xF8\x06\xCC\x31\x54\x75\xCC\x6F\x0D\x9C\x66\xE1\xB6'
            b'\x23\x71\xD4\x5C\xE2\x39\x2E\x1A\xC9\x28\x44\xC3\x10\x10\x2F\x15'
            b'\x6A\x0D\x8D\x52\xC1\xF4\xC4\x0B\xA3\xAA\x65\x09\x57\x86\xCB\x76'
            b'\x97\x57\xA6\x56\x3B\xA9\x58\xFE\xD0\xBC\xC9\x84\xE8\xB5\x17\xA3'
            b'\xD5\xF5\x15\xB2\x3B\x8A\x41\xE7\x4A\xA8\x67\x69\x3F\x90\xDF\xB0'
            b'\x61\xA6\xE8\x6D\xFA\xAE\xE6\x44\x72\xC0\x0E\x5F\x20\x94\x57\x29'
            b'\xCB\xEB\xE7\x7F\x06\xCE\x78\xE0\x8F\x40\x98\xFB\xA4\x1F\x9D\x61'
            b'\x93\xC0\x31\x7E\x8B\x60\xD4\xB6\x08\x4A\xCB\x42\xD2\x9E\x38\x08'
            b'\xA3\xBC\x37\x2D\x85\xE3\x31\x17\x0F\xCB\xF7\xCC\x72\xD0\xB7\x1C'
            b'\x29\x66\x48\xB3\xA4\xD1\x0F\x41\x62\x95\xD0\x80\x7A\xA6\x25\xCA'
            b'\xB2\x74\x4F\xD9\xEA\x8F\xD2\x23\xC4\x25\x37\x02\x98\x28\xBD\x16'
            b'\xBE\x02\x54\x6F\x13\x0F\xD2\xE3\x3B\x93\x6D\x26\x76\xE0\x8A\xED'
            b'\x1B\x73\x31\x8B\x75\x0A\x01\x67\xD0\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x01\x07\x08\x00\x00\x00\x10'
            b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'
            b'\x42\x00\xC3\x08\x00\x00\x00\x80'
            b'\x6B\xC3\xA0\x66\x56\x84\x29\x30\xA2\x47\xE3\x0D\x58\x64\xB4\xD8'
            b'\x19\x23\x6B\xA7\xC6\x89\x65\x86\x2A\xD7\xDB\xC4\xE2\x4A\xF2\x8E'
            b'\x86\xBB\x53\x1F\x03\x35\x8B\xE5\xFB\x74\x77\x7C\x60\x86\xF8\x50'
            b'\xCA\xEF\x89\x3F\x0D\x6F\xCC\x2D\x0C\x91\xEC\x01\x36\x93\xB4\xEA'
            b'\x00\xB8\x0C\xD4\x9A\xAC\x4E\xCB\x5F\x89\x11\xAF\xE5\x39\xAD\xA4'
            b'\xA8\xF3\x82\x3D\x1D\x13\xE4\x72\xD1\x49\x05\x47\xC6\x59\xC7\x61'
            b'\x7F\x3D\x24\x08\x7D\xDB\x6F\x2B\x72\x09\x61\x67\xFC\x09\x7C\xAB'
            b'\x18\xE9\xA4\x58\xFC\xB6\x34\xCD\xCE\x8E\xE3\x58\x94\xC4\x84\xD7'
            b'\x42\x00\xD6\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xD7\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xD8\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00'
        )

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Sections 3.1.3 and 14.1. The rest of the encoding was built by
        # hand.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 49a1ca88-6bea-4fb2-b450-7e58802c3038
        #     Cryptographic Parameters
        #         Digital Signature Algorithm - SHA 256 with RSA
        #     Signature Data
        #         0x6BC3A06656842930A247E30D5864B4D819236BA7C68965862AD7DBC4E2
        #         4AF28E86BB531F03358BE5FB74777C6086F850CAEF893F0D6FCC2D0C91EC
        #         013693B4EA00B80CD49AAC4ECB5F8911AFE539ADA4A8F3823D1D13E472D1
        #         490547C659C7617F3D24087DDB6F2B72096167FC097CAB18E9A458FCB634
        #         CDCE8EE35894C484D7

        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\xD0'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
            b'\x42\x00\x2B\x01\x00\x00\x00\x10'
            b'\x42\x00\xAE\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xC3\x08\x00\x00\x00\x80'
            b'\x6B\xC3\xA0\x66\x56\x84\x29\x30\xA2\x47\xE3\x0D\x58\x64\xB4\xD8'
            b'\x19\x23\x6B\xA7\xC6\x89\x65\x86\x2A\xD7\xDB\xC4\xE2\x4A\xF2\x8E'
            b'\x86\xBB\x53\x1F\x03\x35\x8B\xE5\xFB\x74\x77\x7C\x60\x86\xF8\x50'
            b'\xCA\xEF\x89\x3F\x0D\x6F\xCC\x2D\x0C\x91\xEC\x01\x36\x93\xB4\xEA'
            b'\x00\xB8\x0C\xD4\x9A\xAC\x4E\xCB\x5F\x89\x11\xAF\xE5\x39\xAD\xA4'
            b'\xA8\xF3\x82\x3D\x1D\x13\xE4\x72\xD1\x49\x05\x47\xC6\x59\xC7\x61'
            b'\x7F\x3D\x24\x08\x7D\xDB\x6F\x2B\x72\x09\x61\x67\xFC\x09\x7C\xAB'
            b'\x18\xE9\xA4\x58\xFC\xB6\x34\xCD\xCE\x8E\xE3\x58\x94\xC4\x84\xD7'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

        self.data = (
            b'\xCD\xC8\x7D\xA2\x23\xD7\x86\xDF\x3B\x45\xE0\xBB\xBC\x72\x13\x26'
            b'\xD1\xEE\x2A\xF8\x06\xCC\x31\x54\x75\xCC\x6F\x0D\x9C\x66\xE1\xB6'
            b'\x23\x71\xD4\x5C\xE2\x39\x2E\x1A\xC9\x28\x44\xC3\x10\x10\x2F\x15'
            b'\x6A\x0D\x8D\x52\xC1\xF4\xC4\x0B\xA3\xAA\x65\x09\x57\x86\xCB\x76'
            b'\x97\x57\xA6\x56\x3B\xA9\x58\xFE\xD0\xBC\xC9\x84\xE8\xB5\x17\xA3'
            b'\xD5\xF5\x15\xB2\x3B\x8A\x41\xE7\x4A\xA8\x67\x69\x3F\x90\xDF\xB0'
            b'\x61\xA6\xE8\x6D\xFA\xAE\xE6\x44\x72\xC0\x0E\x5F\x20\x94\x57\x29'
            b'\xCB\xEB\xE7\x7F\x06\xCE\x78\xE0\x8F\x40\x98\xFB\xA4\x1F\x9D\x61'
            b'\x93\xC0\x31\x7E\x8B\x60\xD4\xB6\x08\x4A\xCB\x42\xD2\x9E\x38\x08'
            b'\xA3\xBC\x37\x2D\x85\xE3\x31\x17\x0F\xCB\xF7\xCC\x72\xD0\xB7\x1C'
            b'\x29\x66\x48\xB3\xA4\xD1\x0F\x41\x62\x95\xD0\x80\x7A\xA6\x25\xCA'
            b'\xB2\x74\x4F\xD9\xEA\x8F\xD2\x23\xC4\x25\x37\x02\x98\x28\xBD\x16'
            b'\xBE\x02\x54\x6F\x13\x0F\xD2\xE3\x3B\x93\x6D\x26\x76\xE0\x8A\xED'
            b'\x1B\x73\x31\x8B\x75\x0A\x01\x67\xD0'
        )
        self.digested_data = (
            b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'
        )
        self.signature_data = (
            b'\x6B\xC3\xA0\x66\x56\x84\x29\x30\xA2\x47\xE3\x0D\x58\x64\xB4\xD8'
            b'\x19\x23\x6B\xA7\xC6\x89\x65\x86\x2A\xD7\xDB\xC4\xE2\x4A\xF2\x8E'
            b'\x86\xBB\x53\x1F\x03\x35\x8B\xE5\xFB\x74\x77\x7C\x60\x86\xF8\x50'
            b'\xCA\xEF\x89\x3F\x0D\x6F\xCC\x2D\x0C\x91\xEC\x01\x36\x93\xB4\xEA'
            b'\x00\xB8\x0C\xD4\x9A\xAC\x4E\xCB\x5F\x89\x11\xAF\xE5\x39\xAD\xA4'
            b'\xA8\xF3\x82\x3D\x1D\x13\xE4\x72\xD1\x49\x05\x47\xC6\x59\xC7\x61'
            b'\x7F\x3D\x24\x08\x7D\xDB\x6F\x2B\x72\x09\x61\x67\xFC\x09\x7C\xAB'
            b'\x18\xE9\xA4\x58\xFC\xB6\x34\xCD\xCE\x8E\xE3\x58\x94\xC4\x84\xD7'
        )

    def tearDown(self):
        super(TestSignatureVerifyRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a SignatureVerify request payload can be constructed with no
        arguments.
        """
        payload = signature_verify.SignatureVerifyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.digested_data)
        self.assertEqual(None, payload.signature_data)
        self.assertEqual(None, payload.correlation_value)
        self.assertEqual(None, payload.init_indicator)
        self.assertEqual(None, payload.final_indicator)

    def test_init_with_args(self):
        """
        Test that a SignatureVerify request payload can be constructed with
        valid values
        """
        payload = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            cryptographic_parameters=attributes.CryptographicParameters(),
            data=b'\x01\x02\x03',
            digested_data=b'\x11\x22\x33',
            signature_data=b'\x10\x20\x30',
            correlation_value=b'\xFF',
            init_indicator=False,
            final_indicator=True
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(
            attributes.CryptographicParameters(),
            payload.cryptographic_parameters
        )
        self.assertEqual(b'\x01\x02\x03', payload.data)
        self.assertEqual(b'\x11\x22\x33', payload.digested_data)
        self.assertEqual(b'\x10\x20\x30', payload.signature_data)
        self.assertEqual(b'\xFF', payload.correlation_value)
        self.assertEqual(False, payload.init_indicator)
        self.assertEqual(True, payload.final_indicator)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a SignatureVerify request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_cryptographic_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the cryptographic parameters of a SignatureVerify request payload.
        """
        kwargs = {'cryptographic_parameters': 0}
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a CryptographicParameters "
            "struct.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'cryptographic_parameters', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Cryptographic parameters must be a CryptographicParameters "
            "struct.",
            setattr,
            *args
        )

    def test_invalid_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the data of a SignatureVerify request payload.
        """
        kwargs = {'data': 0}
        self.assertRaisesRegex(
            TypeError,
            "Data must be bytes.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'data', 0)
        self.assertRaisesRegex(
            TypeError,
            "Data must be bytes.",
            setattr,
            *args
        )

    def test_invalid_digested_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the digested data of a SignatureVerify request payload.
        """
        kwargs = {'digested_data': 0}
        self.assertRaisesRegex(
            TypeError,
            "Digested data must be bytes.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'digested_data', 0)
        self.assertRaisesRegex(
            TypeError,
            "Digested data must be bytes.",
            setattr,
            *args
        )

    def test_invalid_signature_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the signature data of a SignatureVerify request payload.
        """
        kwargs = {'signature_data': 0}
        self.assertRaisesRegex(
            TypeError,
            "Signature data must be bytes.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'signature_data', 0)
        self.assertRaisesRegex(
            TypeError,
            "Signature data must be bytes.",
            setattr,
            *args
        )

    def test_invalid_correlation_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the correlation value of a SignatureVerify request payload.
        """
        kwargs = {'correlation_value': 0}
        self.assertRaisesRegex(
            TypeError,
            "Correlation value must be bytes.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'correlation_value', 0)
        self.assertRaisesRegex(
            TypeError,
            "Correlation value must be bytes.",
            setattr,
            *args
        )

    def test_invalid_init_indicator(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the init indicator of a SignatureVerify request payload.
        """
        kwargs = {'init_indicator': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Init indicator must be a boolean.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'init_indicator', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Init indicator must be a boolean.",
            setattr,
            *args
        )

    def test_invalid_final_indicator(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the final indicator of a SignatureVerify request payload.
        """
        kwargs = {'final_indicator': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Final indicator must be a boolean.",
            signature_verify.SignatureVerifyRequestPayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyRequestPayload()
        args = (payload, 'final_indicator', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Final indicator must be a boolean.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a SignatureVerify request payload can be read from a data
        stream.
        """
        payload = signature_verify.SignatureVerifyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.digested_data)
        self.assertEqual(None, payload.signature_data)
        self.assertEqual(None, payload.correlation_value)
        self.assertEqual(None, payload.init_indicator)
        self.assertEqual(None, payload.final_indicator)

        payload.read(self.full_encoding)

        self.assertEqual(
            '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            payload.unique_identifier
        )
        self.assertIsInstance(
            payload.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            payload.cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(self.data, payload.data)
        self.assertEqual(self.digested_data, payload.digested_data)
        self.assertEqual(self.signature_data, payload.signature_data)
        self.assertEqual(b'\x01', payload.correlation_value)
        self.assertEqual(True, payload.init_indicator)
        self.assertEqual(False, payload.final_indicator)

    def test_read_partial(self):
        """
        Test that a SignatureVerify request payload can be read from a partial
        data stream containing the minimum required attributes.
        """
        payload = signature_verify.SignatureVerifyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.digested_data)
        self.assertEqual(None, payload.signature_data)
        self.assertEqual(None, payload.correlation_value)
        self.assertEqual(None, payload.init_indicator)
        self.assertEqual(None, payload.final_indicator)

        payload.read(self.partial_encoding)

        self.assertEqual(
            '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            payload.unique_identifier
        )
        self.assertIsInstance(
            payload.cryptographic_parameters,
            attributes.CryptographicParameters
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            payload.cryptographic_parameters.digital_signature_algorithm
        )
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.digested_data)
        self.assertEqual(self.signature_data, payload.signature_data)
        self.assertEqual(None, payload.correlation_value)
        self.assertEqual(None, payload.init_indicator)
        self.assertEqual(None, payload.final_indicator)

    def test_read_empty(self):
        """
        Test that a SignatureVerify request payload can be read from an empty
        data stream containing the minimum required attributes.
        """
        payload = signature_verify.SignatureVerifyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.digested_data)
        self.assertEqual(None, payload.signature_data)
        self.assertEqual(None, payload.correlation_value)
        self.assertEqual(None, payload.init_indicator)
        self.assertEqual(None, payload.final_indicator)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.cryptographic_parameters)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.digested_data)
        self.assertEqual(None, payload.signature_data)
        self.assertEqual(None, payload.correlation_value)
        self.assertEqual(None, payload.init_indicator)
        self.assertEqual(None, payload.final_indicator)

    def test_write(self):
        """
        Test that a SignatureVerify request payload can be written to a data
        stream.
        """
        payload = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
            ),
            data=self.data,
            digested_data=self.digested_data,
            signature_data=self.signature_data,
            correlation_value=b'\x01',
            init_indicator=True,
            final_indicator=False
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined SignatureVerify request payload can be
        written to a data stream.
        """
        payload = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
            ),
            signature_data=self.signature_data
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty SignatureVerify request payload can be written to a
        data stream.
        """
        payload = signature_verify.SignatureVerifyRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        SignatureVerify request payloads with the same data.
        """
        a = signature_verify.SignatureVerifyRequestPayload()
        b = signature_verify.SignatureVerifyRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
            ),
            data=self.data,
            digested_data=self.digested_data,
            signature_data=self.signature_data,
            correlation_value=b'\x01',
            init_indicator=True,
            final_indicator=False
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
            ),
            data=self.data,
            digested_data=self.digested_data,
            signature_data=self.signature_data,
            correlation_value=b'\x01',
            init_indicator=True,
            final_indicator=False
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different unique identifiers.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='a'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different cryptographic
        parameters.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.
                DigitalSignatureAlgorithm.DSA_WITH_SHA1
            )
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.
                DigitalSignatureAlgorithm.ECDSA_WITH_SHA256
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different data.
        """
        a = signature_verify.SignatureVerifyRequestPayload(data=b'\x11')
        b = signature_verify.SignatureVerifyRequestPayload(data=b'\xFF')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_digested_data(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different digested data.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            digested_data=b'\x00\x01\x02\x03'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            digested_data=b'\xAA\xBB\xCC\xDD'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_signature_data(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different signature data.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            signature_data=b'\x00\x00\x00\x00'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            signature_data=b'\xFF\xFF\xFF\xFF'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_correlation_value(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different correlation values.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            correlation_value=b'\x01'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            correlation_value=b'\x02'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_init_indicator(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different init indicators.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            init_indicator=True
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            init_indicator=False
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_final_indicator(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different final indicators.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            final_indicator=False
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            final_indicator=True
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify request payloads with different types.
        """
        a = signature_verify.SignatureVerifyRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        SignatureVerify request payloads with the same data.
        """
        a = signature_verify.SignatureVerifyRequestPayload()
        b = signature_verify.SignatureVerifyRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
            ),
            data=self.data,
            digested_data=self.digested_data,
            signature_data=self.signature_data,
            correlation_value=b'\x01',
            init_indicator=True,
            final_indicator=False
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
            ),
            data=self.data,
            digested_data=self.digested_data,
            signature_data=self.signature_data,
            correlation_value=b'\x01',
            init_indicator=True,
            final_indicator=False
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different unique identifiers.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='a'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_cryptographic_parameters(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different cryptographic
        parameters.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.
                DigitalSignatureAlgorithm.DSA_WITH_SHA1
            )
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.
                DigitalSignatureAlgorithm.ECDSA_WITH_SHA256
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different data.
        """
        a = signature_verify.SignatureVerifyRequestPayload(data=b'\x11')
        b = signature_verify.SignatureVerifyRequestPayload(data=b'\xFF')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_digested_data(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different digested data.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            digested_data=b'\x00\x01\x02\x03'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            digested_data=b'\xAA\xBB\xCC\xDD'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_signature_data(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different signature data.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            signature_data=b'\x00\x00\x00\x00'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            signature_data=b'\xFF\xFF\xFF\xFF'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_correlation_value(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different correlation values.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            correlation_value=b'\x01'
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            correlation_value=b'\x02'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_init_indicator(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different init indicators.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            init_indicator=True
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            init_indicator=False
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_final_indicator(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different final indicators.
        """
        a = signature_verify.SignatureVerifyRequestPayload(
            final_indicator=False
        )
        b = signature_verify.SignatureVerifyRequestPayload(
            final_indicator=True
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify request payloads with different types.
        """
        a = signature_verify.SignatureVerifyRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a SignatureVerify request payload.
        """
        payload = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=attributes.CryptographicParameters(
                digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
                SHA256_WITH_RSA_ENCRYPTION,
            ),
            data=b'\x00\x11\x22\x33',
            digested_data=b'\x01\x03\x05\x07',
            signature_data=b'\xFF\xFF\xFF\xFF',
            correlation_value=b'\x01',
            init_indicator=True,
            final_indicator=False
        )
        expected = (
            "SignatureVerifyRequestPayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "cryptographic_parameters=CryptographicParameters("
            "block_cipher_mode=None, "
            "padding_method=None, "
            "hashing_algorithm=None, "
            "key_role_type=None, "
            "digital_signature_algorithm="
            "DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION, "
            "cryptographic_algorithm=None, "
            "random_iv=None, "
            "iv_length=None, "
            "tag_length=None, "
            "fixed_field_length=None, "
            "invocation_field_length=None, "
            "counter_length=None, "
            "initial_counter_value=None), "
            "data=" + str(b'\x00\x11\x22\x33') + ", "
            "digested_data=" + str(b'\x01\x03\x05\x07') + ", "
            "signature_data=" + str(b'\xFF\xFF\xFF\xFF') + ", "
            "correlation_value=" + str(b'\x01') + ", "
            "init_indicator=True, "
            "final_indicator=False)"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a SignatureVerify request payload
        """
        cryptographic_parameters = attributes.CryptographicParameters(
            digital_signature_algorithm=enums.
            DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION
        )
        payload = signature_verify.SignatureVerifyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            cryptographic_parameters=cryptographic_parameters,
            data=b'\x00\x11\x22\x33',
            digested_data=b'\x01\x03\x05\x07',
            signature_data=b'\xFF\xFF\xFF\xFF',
            correlation_value=b'\x01',
            init_indicator=True,
            final_indicator=False
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'cryptographic_parameters': cryptographic_parameters,
            'data': b'\x00\x11\x22\x33',
            'digested_data': b'\x01\x03\x05\x07',
            'signature_data': b'\xFF\xFF\xFF\xFF',
            'correlation_value': b'\x01',
            'init_indicator': True,
            'final_indicator': False
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

    def test_read_valid(self):
        """
        Test that a SignatureVerify response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_unique_identifier()

    def test_write_valid(self):
        """
        Test that a SignatureVerify response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a SignatureVerify response payload can be read and written
        without changing the encoded bytes.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_unique_identifier()

    def test_eq(self):
        """
        Test that two SignatureVerify response payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two SignatureVerify response payloads with different data are
        not equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

    def test_read_valid(self):
        """
        Test that a SignatureVerify request payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = signature_verify.SignatureVerifyRequestPayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a SignatureVerify request payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a SignatureVerify request payload can be read and written
        without changing the encoded bytes.
        """
        payload = signature_verify.SignatureVerifyRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_unique_identifier()

    def test_eq(self):
        """
        Test that two SignatureVerify request payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two SignatureVerify request payloads with different data are
        not equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()

class TestSignatureVerifyResponsePayload(testtools.TestCase):
    """
    Test suite for the SignatureVerify response payload.
    """

    def setUp(self):
        super(TestSignatureVerifyResponsePayload, self).setUp()

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Sections 3.1.3 and 14.1. The rest of the encoding was built by
        # hand.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 49a1ca88-6bea-4fb2-b450-7e58802c3038
        #     Validity Indicator - Valid
        #     Data
        #         0xCDC87DA223D786DF3B45E0BBBC721326D1EE2AF806CC315475CC6F0D9C
        #         66E1B62371D45CE2392E1AC92844C310102F156A0D8D52C1F4C40BA3AA65
        #         095786CB769757A6563BA958FED0BCC984E8B517A3D5F515B23B8A41E74A
        #         A867693F90DFB061A6E86DFAAEE64472C00E5F20945729CBEBE77F06CE78
        #         E08F4098FBA41F9D6193C0317E8B60D4B6084ACB42D29E3808A3BC372D85
        #         E331170FCBF7CC72D0B71C296648B3A4D10F416295D0807AA625CAB2744F
        #         D9EA8FD223C42537029828BD16BE02546F130FD2E33B936D2676E08AED1B
        #         73318B750A0167D0
        #     Correlation Value - 1

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x01\x38'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
            b'\x42\x00\x9B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xC2\x08\x00\x00\x00\xD9'
            b'\xCD\xC8\x7D\xA2\x23\xD7\x86\xDF\x3B\x45\xE0\xBB\xBC\x72\x13\x26'
            b'\xD1\xEE\x2A\xF8\x06\xCC\x31\x54\x75\xCC\x6F\x0D\x9C\x66\xE1\xB6'
            b'\x23\x71\xD4\x5C\xE2\x39\x2E\x1A\xC9\x28\x44\xC3\x10\x10\x2F\x15'
            b'\x6A\x0D\x8D\x52\xC1\xF4\xC4\x0B\xA3\xAA\x65\x09\x57\x86\xCB\x76'
            b'\x97\x57\xA6\x56\x3B\xA9\x58\xFE\xD0\xBC\xC9\x84\xE8\xB5\x17\xA3'
            b'\xD5\xF5\x15\xB2\x3B\x8A\x41\xE7\x4A\xA8\x67\x69\x3F\x90\xDF\xB0'
            b'\x61\xA6\xE8\x6D\xFA\xAE\xE6\x44\x72\xC0\x0E\x5F\x20\x94\x57\x29'
            b'\xCB\xEB\xE7\x7F\x06\xCE\x78\xE0\x8F\x40\x98\xFB\xA4\x1F\x9D\x61'
            b'\x93\xC0\x31\x7E\x8B\x60\xD4\xB6\x08\x4A\xCB\x42\xD2\x9E\x38\x08'
            b'\xA3\xBC\x37\x2D\x85\xE3\x31\x17\x0F\xCB\xF7\xCC\x72\xD0\xB7\x1C'
            b'\x29\x66\x48\xB3\xA4\xD1\x0F\x41\x62\x95\xD0\x80\x7A\xA6\x25\xCA'
            b'\xB2\x74\x4F\xD9\xEA\x8F\xD2\x23\xC4\x25\x37\x02\x98\x28\xBD\x16'
            b'\xBE\x02\x54\x6F\x13\x0F\xD2\xE3\x3B\x93\x6D\x26\x76\xE0\x8A\xED'
            b'\x1B\x73\x31\x8B\x75\x0A\x01\x67\xD0\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xD6\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
        )

        # Encoding obtained in part from the KMIP 1.1 testing document,
        # Sections 3.1.3 and 14.1. The rest of the encoding was built by
        # hand.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 49a1ca88-6bea-4fb2-b450-7e58802c3038
        #     Validity Indicator - Valid

        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x40'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
            b'\x42\x00\x9B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        self.partial_encoding_missing_unique_id = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x10'
            b'\x42\x00\x9B\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

        self.partial_encoding_missing_validity_ind = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x34\x39\x61\x31\x63\x61\x38\x38\x2D\x36\x62\x65\x61\x2D\x34\x66'
            b'\x62\x32\x2D\x62\x34\x35\x30\x2D\x37\x65\x35\x38\x38\x30\x32\x63'
            b'\x33\x30\x33\x38\x00\x00\x00\x00'
        )

        self.data = (
            b'\xCD\xC8\x7D\xA2\x23\xD7\x86\xDF\x3B\x45\xE0\xBB\xBC\x72\x13\x26'
            b'\xD1\xEE\x2A\xF8\x06\xCC\x31\x54\x75\xCC\x6F\x0D\x9C\x66\xE1\xB6'
            b'\x23\x71\xD4\x5C\xE2\x39\x2E\x1A\xC9\x28\x44\xC3\x10\x10\x2F\x15'
            b'\x6A\x0D\x8D\x52\xC1\xF4\xC4\x0B\xA3\xAA\x65\x09\x57\x86\xCB\x76'
            b'\x97\x57\xA6\x56\x3B\xA9\x58\xFE\xD0\xBC\xC9\x84\xE8\xB5\x17\xA3'
            b'\xD5\xF5\x15\xB2\x3B\x8A\x41\xE7\x4A\xA8\x67\x69\x3F\x90\xDF\xB0'
            b'\x61\xA6\xE8\x6D\xFA\xAE\xE6\x44\x72\xC0\x0E\x5F\x20\x94\x57\x29'
            b'\xCB\xEB\xE7\x7F\x06\xCE\x78\xE0\x8F\x40\x98\xFB\xA4\x1F\x9D\x61'
            b'\x93\xC0\x31\x7E\x8B\x60\xD4\xB6\x08\x4A\xCB\x42\xD2\x9E\x38\x08'
            b'\xA3\xBC\x37\x2D\x85\xE3\x31\x17\x0F\xCB\xF7\xCC\x72\xD0\xB7\x1C'
            b'\x29\x66\x48\xB3\xA4\xD1\x0F\x41\x62\x95\xD0\x80\x7A\xA6\x25\xCA'
            b'\xB2\x74\x4F\xD9\xEA\x8F\xD2\x23\xC4\x25\x37\x02\x98\x28\xBD\x16'
            b'\xBE\x02\x54\x6F\x13\x0F\xD2\xE3\x3B\x93\x6D\x26\x76\xE0\x8A\xED'
            b'\x1B\x73\x31\x8B\x75\x0A\x01\x67\xD0'
        )

    def tearDown(self):
        super(TestSignatureVerifyResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a SignatureVerify response payload can be constructed with no
        arguments.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.validity_indicator)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.correlation_value)

    def test_init_with_args(self):
        """
        Test that a SignatureVerify response payload can be constructed with
        valid values
        """
        payload = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='00000000-1111-2222-3333-444444444444',
            validity_indicator=enums.ValidityIndicator.VALID,
            data=b'\x01\x02\x03',
            correlation_value=b'\xFF'
        )

        self.assertEqual(
            '00000000-1111-2222-3333-444444444444',
            payload.unique_identifier
        )
        self.assertEqual(
            enums.ValidityIndicator.VALID,
            payload.validity_indicator
        )
        self.assertEqual(b'\x01\x02\x03', payload.data)
        self.assertEqual(b'\xFF', payload.correlation_value)

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a SignatureVerify response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            signature_verify.SignatureVerifyResponsePayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyResponsePayload()
        args = (payload, 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_validity_indicator(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validity indicator of a SignatureVerify response payload.
        """
        kwargs = {'validity_indicator': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Validity indicator must be a ValidityIndicator enumeration.",
            signature_verify.SignatureVerifyResponsePayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyResponsePayload()
        args = (payload, 'validity_indicator', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Validity indicator must be a ValidityIndicator enumeration.",
            setattr,
            *args
        )

    def test_invalid_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the data of a SignatureVerify request payload.
        """
        kwargs = {'data': 0}
        self.assertRaisesRegex(
            TypeError,
            "Data must be bytes.",
            signature_verify.SignatureVerifyResponsePayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyResponsePayload()
        args = (payload, 'data', 0)
        self.assertRaisesRegex(
            TypeError,
            "Data must be bytes.",
            setattr,
            *args
        )

    def test_invalid_correlation_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the correlation value of a SignatureVerify request payload.
        """
        kwargs = {'correlation_value': 0}
        self.assertRaisesRegex(
            TypeError,
            "Correlation value must be bytes.",
            signature_verify.SignatureVerifyResponsePayload,
            **kwargs
        )

        payload = signature_verify.SignatureVerifyResponsePayload()
        args = (payload, 'correlation_value', 0)
        self.assertRaisesRegex(
            TypeError,
            "Correlation value must be bytes.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a SignatureVerify response payload can be read from a data
        stream.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.validity_indicator)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.correlation_value)

        payload.read(self.full_encoding)

        self.assertEqual(
            '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            payload.unique_identifier
        )
        self.assertEqual(
            enums.ValidityIndicator.VALID,
            payload.validity_indicator
        )
        self.assertEqual(self.data, payload.data)
        self.assertEqual(b'\x01', payload.correlation_value)

    def test_read_partial(self):
        """
        Test that a SignatureVerify response payload can be read from a partial
        data stream containing the minimum required attributes.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.validity_indicator)
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.correlation_value)

        payload.read(self.partial_encoding)

        self.assertEqual(
            '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            payload.unique_identifier
        )
        self.assertEqual(
            enums.ValidityIndicator.VALID,
            payload.validity_indicator
        )
        self.assertEqual(None, payload.data)
        self.assertEqual(None, payload.correlation_value)

    def test_read_missing_unique_identifier(self):
        """
        Test that a ValueError gets raised when a required
        SignatureVerifyResponsePayload field is missing when decoding the
        struct.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()
        args = (self.partial_encoding_missing_unique_id, )
        self.assertRaisesRegex(
            ValueError,
            "Parsed payload encoding is missing the unique identifier field.",
            payload.read,
            *args
        )

    def test_read_missing_validity_indicator(self):
        """
        Test that a ValueError gets raised when a required
        SignatureVerifyResponsePayload field is missing when decoding the
        struct.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()
        args = (self.partial_encoding_missing_validity_ind, )
        self.assertRaisesRegex(
            ValueError,
            "Parsed payload encoding is missing the validity indicator field.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a SignatureVerify response payload can be written to a data
        stream.
        """
        payload = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.VALID,
            data=self.data,
            correlation_value=b'\x01'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partially defined SignatureVerify response payload can be
        written to a data stream.
        """
        payload = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.VALID
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_missing_unique_identifier(self):
        """
        Test that a ValueError gets raised when a required
        SignatureVerifyResponsePayload field is missing when encoding the
        struct.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Payload is missing the unique identifier field.",
            payload.write,
            *args
        )

    def test_write_missing_validity_indicator(self):
        """
        Test that a ValueError gets raised when a required
        SignatureVerifyResponsePayload field is missing when encoding the
        struct.
        """
        payload = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038'
        )
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Payload is missing the validity indicator field.",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        SignatureVerify response payloads with the same data.
        """
        a = signature_verify.SignatureVerifyResponsePayload()
        b = signature_verify.SignatureVerifyResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.INVALID,
            data=self.data,
            correlation_value=b'\x01'
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.INVALID,
            data=self.data,
            correlation_value=b'\x01'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify response payloads with different unique identifiers.
        """
        a = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='a'
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validity_indicator(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify response payloads with different validity indicators.
        """
        a = signature_verify.SignatureVerifyResponsePayload(
            validity_indicator=enums.ValidityIndicator.VALID
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            validity_indicator=enums.ValidityIndicator.INVALID
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify response payloads with different data.
        """
        a = signature_verify.SignatureVerifyResponsePayload(data=b'\x11')
        b = signature_verify.SignatureVerifyResponsePayload(data=b'\xFF')

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_correlation_value(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify response payloads with different correlation values.
        """
        a = signature_verify.SignatureVerifyResponsePayload(
            correlation_value=b'\x01'
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            correlation_value=b'\x02'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        SignatureVerify response payloads with different types.
        """
        a = signature_verify.SignatureVerifyResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        SignatureVerify response payloads with the same data.
        """
        a = signature_verify.SignatureVerifyResponsePayload()
        b = signature_verify.SignatureVerifyResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.INVALID,
            data=self.data,
            correlation_value=b'\x01'
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.INVALID,
            data=self.data,
            correlation_value=b'\x01'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify response payloads with different unique identifiers.
        """
        a = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='a'
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validity_indicator(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify response payloads with different validity indicators.
        """
        a = signature_verify.SignatureVerifyResponsePayload(
            validity_indicator=enums.ValidityIndicator.VALID
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            validity_indicator=enums.ValidityIndicator.INVALID
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify response payloads with different data.
        """
        a = signature_verify.SignatureVerifyResponsePayload(data=b'\x11')
        b = signature_verify.SignatureVerifyResponsePayload(data=b'\xFF')

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_correlation_value(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify response payloads with different correlation values.
        """
        a = signature_verify.SignatureVerifyResponsePayload(
            correlation_value=b'\x01'
        )
        b = signature_verify.SignatureVerifyResponsePayload(
            correlation_value=b'\x02'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        SignatureVerify response payloads with different types.
        """
        a = signature_verify.SignatureVerifyResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a SignatureVerify response payload.
        """
        payload = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.VALID,
            data=b'\x00\x11\x22\x33',
            correlation_value=b'\x01'
        )
        expected = (
            "SignatureVerifyResponsePayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "validity_indicator=ValidityIndicator.VALID, "
            "data=" + str(b'\x00\x11\x22\x33') + ", "
            "correlation_value=" + str(b'\x01') + ")"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a SignatureVerify response payload
        """
        payload = signature_verify.SignatureVerifyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            validity_indicator=enums.ValidityIndicator.VALID,
            data=b'\x00\x11\x22\x33',
            correlation_value=b'\x01'
        )

        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'validity_indicator': enums.ValidityIndicator.VALID,
            'data': b'\x00\x11\x22\x33',
            'correlation_value': b'\x01'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

    def test_read_valid(self):
        """
        Test that a SignatureVerify response payload can be read from a valid
        byte stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_unique_identifier()

    def test_write_valid(self):
        """
        Test that a SignatureVerify response payload can be written to a byte
        stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a SignatureVerify response payload can be read and written
        without changing the encoded bytes.
        """
        payload = signature_verify.SignatureVerifyResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_unique_identifier()

    def test_eq(self):
        """
        Test that two SignatureVerify response payloads with the same data are
        equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two SignatureVerify response payloads with different data are
        not equal.
        """
        self.test_not_equal_on_not_equal_unique_identifier()
