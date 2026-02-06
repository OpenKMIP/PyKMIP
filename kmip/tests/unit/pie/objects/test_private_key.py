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

import binascii
import testtools

from kmip.core import enums
from kmip.pie import sqltypes
from kmip.pie.objects import ManagedObject, PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

class TestPrivateKey(testtools.TestCase):
    """
    Test suite for PrivateKey.
    """
    def setUp(self):
        super(TestPrivateKey, self).setUp()

        # Key values taken from Sections 8.2 and 13.4 of the KMIP 1.1
        # testing documentation.
        self.bytes_1024 = (
            b'\x30\x82\x02\x76\x02\x01\x00\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7'
            b'\x0D\x01\x01\x01\x05\x00\x04\x82\x02\x60\x30\x82\x02\x5C\x02\x01'
            b'\x00\x02\x81\x81\x00\x93\x04\x51\xC9\xEC\xD9\x4F\x5B\xB9\xDA\x17'
            b'\xDD\x09\x38\x1B\xD2\x3B\xE4\x3E\xCA\x8C\x75\x39\xF3\x01\xFC\x8A'
            b'\x8C\xD5\xD5\x27\x4C\x3E\x76\x99\xDB\xDC\x71\x1C\x97\xA7\xAA\x91'
            b'\xE2\xC5\x0A\x82\xBD\x0B\x10\x34\xF0\xDF\x49\x3D\xEC\x16\x36\x24'
            b'\x27\xE5\x8A\xCC\xE7\xF6\xCE\x0F\x9B\xCC\x61\x7B\xBD\x8C\x90\xD0'
            b'\x09\x4A\x27\x03\xBA\x0D\x09\xEB\x19\xD1\x00\x5F\x2F\xB2\x65\x52'
            b'\x6A\xAC\x75\xAF\x32\xF8\xBC\x78\x2C\xDE\xD2\xA5\x7F\x81\x1E\x03'
            b'\xEA\xF6\x7A\x94\x4D\xE5\xE7\x84\x13\xDC\xA8\xF2\x32\xD0\x74\xE6'
            b'\xDC\xEA\x4C\xEC\x9F\x02\x03\x01\x00\x01\x02\x81\x80\x0B\x6A\x7D'
            b'\x73\x61\x99\xEA\x48\xA4\x20\xE4\x53\x7C\xA0\xC7\xC0\x46\x78\x4D'
            b'\xCB\xEA\xA6\x3B\xAE\xBC\x0B\xC1\x32\x78\x74\x49\xCD\xE8\xD7\xCA'
            b'\xD0\xC0\xC8\x63\xC0\xFE\xFB\x06\xC3\x06\x2B\xEF\xC5\x00\x33\xEC'
            b'\xF8\x7B\x4E\x33\xA9\xBE\x7B\xCB\xC8\xF1\x51\x1A\xE2\x15\xE8\x0D'
            b'\xEB\x5D\x8A\xF2\xBD\x31\x31\x9D\x78\x21\x19\x66\x40\x93\x5A\x0C'
            b'\xD6\x7C\x94\x59\x95\x79\xF2\x10\x0D\x65\xE0\x38\x83\x1F\xDA\xFB'
            b'\x0D\xBE\x2B\xBD\xAC\x00\xA6\x96\xE6\x7E\x75\x63\x50\xE1\xC9\x9A'
            b'\xCE\x11\xA3\x6D\xAB\xAC\x3E\xD3\xE7\x30\x96\x00\x59\x02\x41\x00'
            b'\xDD\xF6\x72\xFB\xCC\x5B\xDA\x3D\x73\xAF\xFC\x4E\x79\x1E\x0C\x03'
            b'\x39\x02\x24\x40\x5D\x69\xCC\xAA\xBC\x74\x9F\xAA\x0D\xCD\x4C\x25'
            b'\x83\xC7\x1D\xDE\x89\x41\xA7\xB9\xAA\x03\x0F\x52\xEF\x14\x51\x46'
            b'\x6C\x07\x4D\x4D\x33\x8F\xE6\x77\x89\x2A\xCD\x9E\x10\xFD\x35\xBD'
            b'\x02\x41\x00\xA9\x8F\xBC\x3E\xD6\xB4\xC6\xF8\x60\xF9\x71\x65\xAC'
            b'\x2F\x7B\xB6\xF2\xE2\xCB\x19\x2A\x9A\xBD\x49\x79\x5B\xE5\xBC\xF3'
            b'\x7D\x8E\xE6\x9A\x6E\x16\x9C\x24\xE5\xC3\x2E\x4E\x7F\xA3\x32\x65'
            b'\x46\x14\x07\xF9\x52\xBA\x49\xE2\x04\x81\x8A\x2F\x78\x5F\x11\x3F'
            b'\x92\x2B\x8B\x02\x40\x25\x3F\x94\x70\x39\x0D\x39\x04\x93\x03\x77'
            b'\x7D\xDB\xC9\x75\x0E\x9D\x64\x84\x9C\xE0\x90\x3E\xAE\x70\x4D\xC9'
            b'\xF5\x89\xB7\x68\x0D\xEB\x9D\x60\x9F\xD5\xBC\xD4\xDE\xCD\x6F\x12'
            b'\x05\x42\xE5\xCF\xF5\xD7\x6F\x2A\x43\xC8\x61\x5F\xB5\xB3\xA9\x21'
            b'\x34\x63\x79\x7A\xA9\x02\x41\x00\xA1\xDD\xF0\x23\xC0\xCD\x94\xC0'
            b'\x19\xBB\x26\xD0\x9B\x9E\x3C\xA8\xFA\x97\x1C\xB1\x6A\xA5\x8B\x9B'
            b'\xAF\x79\xD6\x08\x1A\x1D\xBB\xA4\x52\xBA\x53\x65\x3E\x28\x04\xBA'
            b'\x98\xFF\x69\xE8\xBB\x1B\x3A\x16\x1E\xA2\x25\xEA\x50\x14\x63\x21'
            b'\x6A\x8D\xAB\x9B\x88\xA7\x5E\x5F\x02\x40\x61\x78\x64\x6E\x11\x2C'
            b'\xF7\x9D\x92\x1A\x8A\x84\x3F\x17\xF6\xE7\xFF\x97\x4F\x68\x81\x22'
            b'\x36\x5B\xF6\x69\x0C\xDF\xC9\x96\xE1\x89\x09\x52\xEB\x38\x20\xDD'
            b'\x18\x90\xEC\x1C\x86\x19\xE8\x7A\x2B\xD3\x8F\x9D\x03\xB3\x7F\xAC'
            b'\x74\x2E\xFB\x74\x8C\x78\x85\x94\x2C\x39')
        self.bytes_2048 = (
            b'\x30\x82\x04\xA5\x02\x01\x00\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C'
            b'\x00\x42\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77'
            b'\x76\x00\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55'
            b'\xF8\x00\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48'
            b'\x34\x6D\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D'
            b'\x7D\xC7\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6'
            b'\x26\x7F\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5'
            b'\xA5\xF4\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49'
            b'\x00\xDF\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD'
            b'\xBC\x7D\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8'
            b'\xA0\xEC\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B'
            b'\xB8\xB7\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8'
            b'\xDA\x7D\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1'
            b'\xB7\xAE\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8'
            b'\xD7\xCC\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8'
            b'\x2D\x73\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29'
            b'\xC6\xFC\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00'
            b'\x01\x02\x82\x01\x00\x3B\x12\x45\x5D\x53\xC1\x81\x65\x16\xC5\x18'
            b'\x49\x3F\x63\x98\xAA\xFA\x72\xB1\x7D\xFA\x89\x4D\xB8\x88\xA7\xD4'
            b'\x8C\x0A\x47\xF6\x25\x79\xA4\xE6\x44\xF8\x6D\xA7\x11\xFE\xC8\x50'
            b'\xCD\xD9\xDB\xBD\x17\xF6\x9A\x44\x3D\x2E\xC1\xDD\x60\xD3\xC6\x18'
            b'\xFA\x74\xCD\xE5\xFD\xAF\xAB\xD6\xBA\xA2\x6E\xB0\xA3\xAD\xB4\xDE'
            b'\xF6\x48\x0F\xB1\x21\x8C\xD3\xB0\x83\xE2\x52\xE8\x85\xB6\xF0\x72'
            b'\x9F\x98\xB2\x14\x4D\x2B\x72\x29\x3E\x1B\x11\xD7\x33\x93\xBC\x41'
            b'\xF7\x5B\x15\xEE\x3D\x75\x69\xB4\x99\x5E\xD1\xA1\x44\x25\xDA\x43'
            b'\x19\xB7\xB2\x6B\x0E\x8F\xEF\x17\xC3\x75\x42\xAE\x5C\x6D\x58\x49'
            b'\xF8\x72\x09\x56\x7F\x39\x25\xA4\x7B\x01\x6D\x56\x48\x59\x71\x7B'
            b'\xC5\x7F\xCB\x45\x22\xD0\xAA\x49\xCE\x81\x6E\x5B\xE7\xB3\x08\x81'
            b'\x93\x23\x6E\xC9\xEF\xFF\x14\x08\x58\x04\x5B\x73\xC5\xD7\x9B\xAF'
            b'\x38\xF7\xC6\x7F\x04\xC5\xDC\xF0\xE3\x80\x6A\xD9\x82\xD1\x25\x90'
            b'\x58\xC3\x47\x3E\x84\x71\x79\xA8\x78\xF2\xC6\xB3\xBD\x96\x8F\xB9'
            b'\x9E\xA4\x6E\x91\x85\x89\x2F\x36\x76\xE7\x89\x65\xC2\xAE\xD4\x87'
            b'\x7B\xA3\x91\x7D\xF0\x7C\x5E\x92\x74\x74\xF1\x9E\x76\x4B\xA6\x1D'
            b'\xC3\x8D\x63\xBF\x29\x02\x81\x81\x00\xD5\xC6\x9C\x8C\x3C\xDC\x24'
            b'\x64\x74\x4A\x79\x37\x13\xDA\xFB\x9F\x1D\xBC\x79\x9F\xF9\x64\x23'
            b'\xFE\xCD\x3C\xBA\x79\x42\x86\xBC\xE9\x20\xF4\xB5\xC1\x83\xF9\x9E'
            b'\xE9\x02\x8D\xB6\x21\x2C\x62\x77\xC4\xC8\x29\x7F\xCF\xBC\xE7\xF7'
            b'\xC2\x4C\xA4\xC5\x1F\xC7\x18\x2F\xB8\xF4\x01\x9F\xB1\xD5\x65\x96'
            b'\x74\xC5\xCB\xE6\xD5\xFA\x99\x20\x51\x34\x17\x60\xCD\x00\x73\x57'
            b'\x29\xA0\x70\xA9\xE5\x4D\x34\x2B\xEB\xA8\xEF\x47\xEE\x82\xD3\xA0'
            b'\x1B\x04\xCE\xC4\xA0\x0D\x4D\xDB\x41\xE3\x51\x16\xFC\x22\x1E\x85'
            b'\x4B\x43\xA6\x96\xC0\xE6\x41\x9B\x1B\x02\x81\x81\x00\xCD\x5E\xA7'
            b'\x70\x27\x89\x06\x4B\x67\x35\x40\xCB\xFF\x09\x35\x6A\xD8\x0B\xC3'
            b'\xD5\x92\x81\x2E\xBA\x47\x61\x0B\x9F\xAC\x6A\xEC\xEF\xE2\x2A\xCA'
            b'\xE4\x38\x45\x9C\xDA\x74\xE5\x96\x53\xD8\x8C\x04\x18\x9D\x34\x39'
            b'\x9B\xF5\xB1\x4B\x92\x0E\x34\xEF\x38\xA7\xD0\x9F\xE6\x95\x93\x39'
            b'\x6E\x8F\xE7\x35\xE6\xF0\xA6\xAE\x49\x90\x40\x10\x41\xD8\xA4\x06'
            b'\xB6\xFD\x86\xA1\x16\x1E\x45\xF9\x5A\x3E\xAA\x5C\x10\x12\xE6\x66'
            b'\x2E\x44\xF1\x5F\x33\x5A\xC9\x71\xE1\x76\x6B\x2B\xB9\xC9\x85\x10'
            b'\x99\x74\x14\x1B\x44\xD3\x7E\x1E\x31\x98\x20\xA5\x5F\x02\x81\x81'
            b'\x00\xB2\x87\x12\x37\xBF\x9F\xAD\x38\xC3\x31\x6A\xB7\x87\x7A\x6A'
            b'\x86\x80\x63\xE5\x42\xA7\x18\x6D\x43\x1E\x8D\x27\xC1\x9A\xC0\x41'
            b'\x45\x84\x03\x39\x42\xE9\xFF\x6E\x29\x73\xBB\x7B\x2D\x8B\x0E\x94'
            b'\xAD\x1E\xE8\x21\x58\x10\x8F\xBC\x86\x64\x51\x7A\x5A\x46\x7F\xB9'
            b'\x63\x01\x4B\xD5\xDC\xC2\xB4\xFB\x08\x7C\x23\x03\x9D\x11\x92\x0D'
            b'\xBE\x22\xFD\x9F\x16\xB4\xD8\x9E\x23\x22\x5C\xD4\x55\xAD\xBA\xF3'
            b'\x2E\xF4\x3F\x18\x58\x64\xA3\x6D\x63\x03\x09\xD6\x85\x3F\x77\x14'
            b'\xB3\x9A\xAE\x1E\xBE\xE3\x93\x8F\x87\xC2\x70\x7E\x17\x8C\x73\x9F'
            b'\x9F\x02\x81\x81\x00\x96\x90\xBE\xD1\x4B\x2A\xFA\xA2\x6D\x98\x6D'
            b'\x59\x22\x31\xEE\x27\xD7\x1D\x49\x06\x5B\xD2\xBA\x1F\x78\x15\x7E'
            b'\x20\x22\x98\x81\xFD\x9D\x23\x22\x7D\x0F\x84\x79\xEA\xEF\xA9\x22'
            b'\xFD\x75\xD5\xB1\x6B\x1A\x56\x1F\xA6\x68\x0B\x04\x0C\xA0\xBD\xCE'
            b'\x65\x0B\x23\xB9\x17\xA4\xB1\xBB\x79\x83\xA7\x4F\xAD\x70\xE1\xC3'
            b'\x05\xCB\xEC\x2B\xFF\x1A\x85\xA7\x26\xA1\xD9\x02\x60\xE4\xF1\x08'
            b'\x4F\x51\x82\x34\xDC\xD3\xFE\x77\x0B\x95\x20\x21\x5B\xD5\x43\xBB'
            b'\x6A\x41\x17\x71\x87\x54\x67\x6A\x34\x17\x16\x66\xA7\x9F\x26\xE7'
            b'\x9C\x14\x9C\x5A\xA1\x02\x81\x81\x00\xA0\xC9\x85\xA0\xA0\xA7\x91'
            b'\xA6\x59\xF9\x97\x31\x13\x4C\x44\xF3\x7B\x2E\x52\x0A\x2C\xEA\x35'
            b'\x80\x0A\xD2\x72\x41\xED\x36\x0D\xFD\xE6\xE8\xCA\x61\x4F\x12\x04'
            b'\x7F\xD0\x8B\x76\xAC\x4D\x13\xC0\x56\xA0\x69\x9E\x2F\x98\xA1\xCA'
            b'\xC9\x10\x11\x29\x4D\x71\x20\x8F\x4A\xBA\xB3\x3B\xA8\x7A\xA0\x51'
            b'\x7F\x41\x5B\xAC\xA8\x8D\x6B\xAC\x00\x60\x88\xFA\x60\x1D\x34\x94'
            b'\x17\xE1\xF0\xC9\xB2\x3A\xFF\xA4\xD4\x96\x61\x8D\xBC\x02\x49\x86'
            b'\xED\x69\x0B\xBB\x7B\x02\x57\x68\xFF\x9D\xF8\xAC\x15\x41\x6F\x48'
            b'\x9F\x81\x29\xC3\x23\x41\xA8\xB4\x4F')
        self.engine = create_engine('sqlite:///:memory:', echo=True)
        sqltypes.Base.metadata.create_all(self.engine)

    def tearDown(self):
        super(TestPrivateKey, self).tearDown()

    def test_init(self):
        """
        Test that a PrivateKey object can be instantiated.
        """
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)

        self.assertEqual(
            key.cryptographic_algorithm, enums.CryptographicAlgorithm.RSA)
        self.assertEqual(key.cryptographic_length, 1024)
        self.assertEqual(key.value, self.bytes_1024)
        self.assertEqual(key.key_format_type, enums.KeyFormatType.PKCS_8)
        self.assertEqual(key.cryptographic_usage_masks, list())
        self.assertEqual(key.names, ['Private Key'])

    def test_init_with_args(self):
        """
        Test that a PrivateKey object can be instantiated with all arguments.
        """
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_1024,
            enums.KeyFormatType.PKCS_8,
            masks=[enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT],
            name='Test Private Key')

        self.assertEqual(key.cryptographic_algorithm,
                         enums.CryptographicAlgorithm.RSA)
        self.assertEqual(key.cryptographic_length, 1024)
        self.assertEqual(key.value, self.bytes_1024)
        self.assertEqual(key.key_format_type, enums.KeyFormatType.PKCS_8)
        self.assertEqual(key.cryptographic_usage_masks,
                         [enums.CryptographicUsageMask.ENCRYPT,
                          enums.CryptographicUsageMask.DECRYPT])
        self.assertEqual(key.names, ['Test Private Key'])

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the PrivateKey.
        """
        expected = enums.ObjectType.PRIVATE_KEY
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        observed = key.object_type
        self.assertEqual(expected, observed)

    def test_validate_on_invalid_algorithm(self):
        """
        Test that a TypeError is raised when an invalid algorithm value is
        used to construct a PrivateKey.
        """
        args = ('invalid', 1024, self.bytes_1024, enums.KeyFormatType.PKCS_8)
        self.assertRaises(TypeError, PrivateKey, *args)

    def test_validate_on_invalid_length(self):
        """
        Test that a TypeError is raised when an invalid length value is used
        to construct a PrivateKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 'invalid', self.bytes_1024,
                enums.KeyFormatType.PKCS_8)
        self.assertRaises(TypeError, PrivateKey, *args)

    def test_validate_on_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a PrivateKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, 0,
                enums.KeyFormatType.PKCS_8)
        self.assertRaises(TypeError, PrivateKey, *args)

    def test_validate_on_invalid_format_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a PrivateKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                'invalid')
        self.assertRaises(TypeError, PrivateKey, *args)

    def test_validate_on_invalid_format_type_value(self):
        """
        Test that a ValueError is raised when an invalid format type is used to
        construct a PrivateKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.OPAQUE)
        self.assertRaises(ValueError, PrivateKey, *args)

    def test_validate_on_invalid_masks(self):
        """
        Test that a TypeError is raised when an invalid masks value is used to
        construct a PrivateKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.PKCS_8)
        kwargs = {'masks': 'invalid'}
        self.assertRaises(TypeError, PrivateKey, *args, **kwargs)

    def test_validate_on_invalid_mask(self):
        """
        Test that a TypeError is raised when an invalid mask value is used to
        construct a PrivateKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.PKCS_8)
        kwargs = {'masks': ['invalid']}
        self.assertRaises(TypeError, PrivateKey, *args, **kwargs)

    def test_validate_on_invalid_name(self):
        """
        Test that a TypeError is raised when an invalid name value is used to
        construct a PrivateKey.
        """
        args = (enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
                enums.KeyFormatType.PKCS_8)
        kwargs = {'name': 0}
        self.assertRaises(TypeError, PrivateKey, *args, **kwargs)

    def test_repr(self):
        """
        Test that repr can be applied to a PrivateKey.
        """
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        args = "{0}, {1}, {2}, {3}, {4}".format(
            "algorithm={0}".format(enums.CryptographicAlgorithm.RSA),
            "length={0}".format(1024),
            "value={0}".format(binascii.hexlify(self.bytes_1024)),
            "format_type={0}".format(enums.KeyFormatType.PKCS_8),
            "key_wrapping_data={0}".format({})
        )
        expected = "PrivateKey({0})".format(args)
        observed = repr(key)
        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a PrivateKey.
        """
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        expected = str(binascii.hexlify(self.bytes_1024))
        observed = str(key)
        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        PrivateKey objects with the same data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.AES, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_length(self):
        """
        Test that the equality operator returns False when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns False when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_2048,
            enums.KeyFormatType.PKCS_8)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_format_type(self):
        """
        Test that the equality operator returns False when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_1)
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_key_wrapping_data(self):
        """
        Test that the equality operator returns False when comparing two
        PrivateKey objects with different key wrapping data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_1024,
            enums.KeyFormatType.PKCS_8,
            key_wrapping_data={}
        )
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_1024,
            enums.KeyFormatType.PKCS_8,
            key_wrapping_data={
                'wrapping_method': enums.WrappingMethod.ENCRYPT
            }
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        PrivateKey object to a non-PrivateKey object.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        b = "invalid"
        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two PrivateKey objects with the same internal data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_algorithm(self):
        """
        Test that the equality operator returns True when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = PrivateKey(
            enums.CryptographicAlgorithm.AES, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_length(self):
        """
        Test that the equality operator returns True when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 1024, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns True when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_1024,
            enums.KeyFormatType.PKCS_8)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_format_type(self):
        """
        Test that the equality operator returns True when comparing two
        PrivateKey objects with different data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_8)
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_key_wrapping_data(self):
        """
        Test that the inequality operator returns True when comparing two
        PrivateKey objects with different key wrapping data.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_1024,
            enums.KeyFormatType.PKCS_8,
            key_wrapping_data={}
        )
        b = PrivateKey(
            enums.CryptographicAlgorithm.RSA,
            1024,
            self.bytes_1024,
            enums.KeyFormatType.PKCS_8,
            key_wrapping_data={
                'wrapping_method': enums.WrappingMethod.ENCRYPT
            }
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        PrivateKey object to a non-PrivateKey object.
        """
        a = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        b = "invalid"
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_save(self):
        """
        Test that the object can be saved using SQLAlchemy. This will add it to
        the database, verify that no exceptions are thrown, and check that its
        unique identifier was set.
        """
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1)
        Session = sessionmaker(bind=self.engine)
        session = Session()
        session.add(key)
        session.commit()
        self.assertIsNotNone(key.unique_identifier)

    def test_get(self):
        """
        Test that the object can be saved and then retrieved using SQLAlchemy.
        This adds is to the database and then retrieves it by ID and verifies
        some of the attributes.
        """
        test_name = 'bowser'
        masks = [enums.CryptographicUsageMask.ENCRYPT,
                 enums.CryptographicUsageMask.WRAP_KEY]
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1, masks=masks, name=test_name)
        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(1, len(get_obj.names))
        self.assertEqual([test_name], get_obj.names)
        self.assertEqual(enums.ObjectType.PRIVATE_KEY, get_obj.object_type)
        self.assertEqual(self.bytes_2048, get_obj.value)
        self.assertEqual(enums.CryptographicAlgorithm.RSA,
                         get_obj.cryptographic_algorithm)
        self.assertEqual(2048, get_obj.cryptographic_length)
        self.assertEqual(enums.KeyFormatType.PKCS_1, get_obj.key_format_type)
        self.assertEqual(masks, get_obj.cryptographic_usage_masks)

    def test_add_multiple_names(self):
        """
        Test that multiple names can be added to a managed object. This
        verifies a few properties. First this verifies that names can be added
        using simple strings. It also verifies that the index for each
        subsequent string is set accordingly. Finally this tests that the names
        can be saved and retrieved from the database.
        """
        expected_names = ['bowser', 'frumpy', 'big fat cat']
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1, name=expected_names[0])
        key.names.append(expected_names[1])
        key.names.append(expected_names[2])
        self.assertEqual(3, key.name_index)
        expected_mo_names = list()
        for i, name in enumerate(expected_names):
            expected_mo_names.append(sqltypes.ManagedObjectName(name, i))
        self.assertEqual(expected_mo_names, key._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_remove_name(self):
        """
        Tests that a name can be removed from the list of names. This will
        verify that the list of names is correct. It will verify that updating
        this object removes the name from the database.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        remove_index = 1
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1, name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])
        key.names.pop(remove_index)
        self.assertEqual(3, key.name_index)

        expected_names = list()
        expected_mo_names = list()
        for i, name in enumerate(names):
            if i != remove_index:
                expected_names.append(name)
                expected_mo_names.append(sqltypes.ManagedObjectName(name, i))
        self.assertEqual(expected_names, key.names)
        self.assertEqual(expected_mo_names, key._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_remove_and_add_name(self):
        """
        Tests that names can be removed from the list of names and more added.
        This will verify that the list of names is correct. It will verify that
        updating this object removes the name from the database. It will verify
        that the indices for the removed names are not reused.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1, name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])
        key.names.pop()
        key.names.pop()
        key.names.append('dog')
        self.assertEqual(4, key.name_index)

        expected_names = ['bowser', 'dog']
        expected_mo_names = list()
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[0],
                                                            0))
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[1],
                                                            3))
        self.assertEqual(expected_names, key.names)
        self.assertEqual(expected_mo_names, key._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_add_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will add a
        name to it in one session, and then retrieve it in another session to
        verify that it has all of the correct names.

        This test and the subsequent test_udpate_* methods are different than
        the name tests above because these are updating objects already stored
        in the database. This tests will simulate what happens when the KMIP
        client calls an add attribute method.
        """
        first_name = 'bowser'
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1, name=first_name)
        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        added_name = 'frumpy'
        expected_names = [first_name, added_name]
        expected_mo_names = list()
        for i, name in enumerate(expected_names):
            expected_mo_names.append(sqltypes.ManagedObjectName(name, i))

        session = Session()
        update_key = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        update_key.names.append(added_name)
        session.commit()

        session = Session()
        get_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_remove_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will
        remove a name from it in one session, and then retrieve it in another
        session to verify that it has all of the correct names.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        remove_index = 1
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1, name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        expected_names = list()
        expected_mo_names = list()
        for i, name in enumerate(names):
            if i != remove_index:
                expected_names.append(name)
                expected_mo_names.append(sqltypes.ManagedObjectName(name, i))

        session = Session()
        update_key = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        update_key.names.pop(remove_index)
        session.commit()

        session = Session()
        get_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_remove_and_add_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will
        remove a name and add another one to it in one session, and then
        retrieve it in another session to verify that it has all of the correct
        names. This simulates multiple operation being sent for the same
        object.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        key = PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.bytes_2048,
            enums.KeyFormatType.PKCS_1, name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        update_key = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        update_key.names.pop()
        update_key.names.pop()
        update_key.names.append('dog')
        session.commit()

        expected_names = ['bowser', 'dog']
        expected_mo_names = list()
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[0],
                                                            0))
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[1],
                                                            3))

        session = Session()
        get_obj = session.query(PrivateKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)
