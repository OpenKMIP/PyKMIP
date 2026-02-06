# Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
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

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime
import mock
import ssl
import testtools

from kmip.core import exceptions
from kmip.services.server.auth import utils

class TestUtils(testtools.TestCase):
    """
    Test suite for authentication utilities.
    """

    def setUp(self):
        super(TestUtils, self).setUp()

        self.certificate_bytes = (
            b'\x30\x82\x03\x7c\x30\x82\x02\x64\xa0\x03\x02\x01\x02\x02\x01\x02'
            b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30'
            b'\x45\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x1f'
            b'\x30\x1d\x06\x03\x55\x04\x0a\x13\x16\x54\x65\x73\x74\x20\x43\x65'
            b'\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x32\x30\x31\x31\x31'
            b'\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x54\x72\x75\x73\x74\x20'
            b'\x41\x6e\x63\x68\x6f\x72\x30\x1e\x17\x0d\x31\x30\x30\x31\x30\x31'
            b'\x30\x38\x33\x30\x30\x30\x5a\x17\x0d\x33\x30\x31\x32\x33\x31\x30'
            b'\x38\x33\x30\x30\x30\x5a\x30\x40\x31\x0b\x30\x09\x06\x03\x55\x04'
            b'\x06\x13\x02\x55\x53\x31\x1f\x30\x1d\x06\x03\x55\x04\x0a\x13\x16'
            b'\x54\x65\x73\x74\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65'
            b'\x73\x20\x32\x30\x31\x31\x31\x10\x30\x0e\x06\x03\x55\x04\x03\x13'
            b'\x07\x47\x6f\x6f\x64\x20\x43\x41\x30\x82\x01\x22\x30\x0d\x06\x09'
            b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00'
            b'\x30\x82\x01\x0a\x02\x82\x01\x01\x00\x90\x58\x9a\x47\x62\x8d\xfb'
            b'\x5d\xf6\xfb\xa0\x94\x8f\x7b\xe5\xaf\x7d\x39\x73\x20\x6d\xb5\x59'
            b'\x0e\xcc\xc8\xc6\xc6\xb4\xaf\xe6\xf2\x67\xa3\x0b\x34\x7a\x73\xe7'
            b'\xff\xa4\x98\x44\x1f\xf3\x9c\x0d\x23\x2c\x5e\xaf\x21\xe6\x45\xda'
            b'\x04\x6a\x96\x2b\xeb\xd2\xc0\x3f\xcf\xce\x9e\x4e\x60\x6a\x6d\x5e'
            b'\x61\x8f\x72\xd8\x43\xb4\x0c\x25\xad\xa7\xe4\x18\xe4\xb8\x1a\xa2'
            b'\x09\xf3\xe9\x3d\x5c\x62\xac\xfa\xf4\x14\x5c\x92\xac\x3a\x4e\x3b'
            b'\x46\xec\xc3\xe8\xf6\x6e\xa6\xae\x2c\xd7\xac\x5a\x2d\x5a\x98\x6d'
            b'\x40\xb6\xe9\x47\x18\xd3\xc1\xa9\x9e\x82\xcd\x1c\x96\x52\xfc\x49'
            b'\x97\xc3\x56\x59\xdd\xde\x18\x66\x33\x65\xa4\x8a\x56\x14\xd1\xe7'
            b'\x50\x69\x9d\x88\x62\x97\x50\xf5\xff\xf4\x7d\x1f\x56\x32\x00\x69'
            b'\x0c\x23\x9c\x60\x1b\xa6\x0c\x82\xba\x65\xa0\xcc\x8c\x0f\xa5\x7f'
            b'\x84\x94\x53\x94\xaf\x7c\xfb\x06\x85\x67\x14\xa8\x48\x5f\x37\xbe'
            b'\x56\x64\x06\x49\x6c\x59\xc6\xf5\x83\x50\xdf\x74\x52\x5d\x2d\x2c'
            b'\x4a\x4b\x82\x4d\xce\x57\x15\x01\xe1\x55\x06\xb9\xfd\x79\x38\x93'
            b'\xa9\x82\x8d\x71\x89\xb2\x0d\x3e\x65\xad\xd7\x85\x5d\x6b\x63\x7d'
            b'\xca\xb3\x4a\x96\x82\x46\x64\xda\x8b\x02\x03\x01\x00\x01\xa3\x7c'
            b'\x30\x7a\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\xe4'
            b'\x7d\x5f\xd1\x5c\x95\x86\x08\x2c\x05\xae\xbe\x75\xb6\x65\xa7\xd9'
            b'\x5d\xa8\x66\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x58\x01'
            b'\x84\x24\x1b\xbc\x2b\x52\x94\x4a\x3d\xa5\x10\x72\x14\x51\xf5\xaf'
            b'\x3a\xc9\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02'
            b'\x01\x06\x30\x17\x06\x03\x55\x1d\x20\x04\x10\x30\x0e\x30\x0c\x06'
            b'\x0a\x60\x86\x48\x01\x65\x03\x02\x01\x30\x01\x30\x0f\x06\x03\x55'
            b'\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff\x30\x0d\x06\x09'
            b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00'
            b'\x35\x87\x97\x16\xe6\x75\x35\xcd\xc0\x12\xff\x96\x5c\x21\x42\xac'
            b'\x27\x6b\x32\xbb\x08\x2d\x96\xb1\x70\x41\xaa\x03\x4f\x5a\x3e\xe6'
            b'\xb6\xf4\x3e\x68\xb1\xbc\xff\x9d\x10\x73\x64\xae\x9f\xba\x36\x56'
            b'\x7c\x05\xf4\x3d\x7c\x51\x47\xbc\x1a\x3d\xee\x3d\x46\x07\xfa\x84'
            b'\x88\xd6\xf0\xdd\xc8\xa7\x23\x98\xc6\xca\x45\x4e\x2b\x93\x47\xa8'
            b'\xdd\x41\xcd\x0d\x7c\x2a\x21\x57\x3d\x09\x04\xbd\xb2\x6c\x95\xfb'
            b'\x1d\x47\x0b\x02\xf8\x4d\x3a\xea\xf8\xb5\xcb\x2b\x1f\xea\x56\x28'
            b'\xf4\x62\xa9\x3e\x50\x97\xc0\xb6\xb8\x36\x8e\x76\x0a\x5e\xc0\xae'
            b'\x14\xc0\x50\x42\x75\x82\x1a\xbc\x1a\xd6\x0d\x53\xa6\x14\x69\xfd'
            b'\x19\x98\x1e\x73\x32\x9d\x81\x66\x66\xb5\xed\xcc\x5c\xfe\x53\xd5'
            b'\xc4\x03\xb0\xbe\x80\xfa\xb8\x92\xa0\xc8\xfe\x25\x5f\x21\x3d\x6c'
            b'\xea\x50\x6d\x74\x1e\x74\x96\xb0\xd5\xc2\x5d\xa8\x61\xf0\x2f\x5b'
            b'\xfe\xac\x0b\x6b\x1e\xd9\x09\x5e\x66\x27\x54\x9a\xbc\xe2\x54\xd3'
            b'\xf8\xa0\x47\x97\x20\xda\x24\x53\xa4\xfa\xa7\xff\xc7\x33\x51\x46'
            b'\x41\x8c\x36\x8c\xeb\xe9\x29\xc2\xad\x58\x24\x80\x9d\xe8\x04\x6e'
            b'\x0b\x06\x63\x30\x13\x2a\x39\x8f\x24\xf2\x74\x9e\x91\xc5\xab\x33'
        )

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=backends.default_backend()
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Jane Doe")
        ])
        subject_no_common_name = issuer_no_common_name = x509.Name([
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Test, Inc.")
        ])
        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        ).sign(private_key, hashes.SHA256(), backends.default_backend())

        self.certificate_no_name = x509.CertificateBuilder().subject_name(
            subject_no_common_name
        ).issuer_name(
            issuer_no_common_name
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA256(), backends.default_backend())

        self.certificate_no_extension = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=1)
        ).sign(private_key, hashes.SHA256(), backends.default_backend())

    def tearDown(self):
        super(TestUtils, self).tearDown()

    def test_get_certificate_from_connection(self):
        """
        Test that the certificate can be retrieved from a provided connection.
        """
        mock_connection = mock.MagicMock(ssl.SSLSocket)
        mock_connection.getpeercert.return_value = self.certificate_bytes
        result = utils.get_certificate_from_connection(
            mock_connection
        )

        self.assertIsInstance(result, x509.Certificate)

    def test_get_certificate_from_connection_with_load_failure(self):
        """
        Test that the right value is returned when the certificate cannot be
        retrieved from the provided connection.
        """
        mock_connection = mock.MagicMock(ssl.SSLSocket)
        mock_connection.getpeercert.return_value = None
        result = utils.get_certificate_from_connection(
            mock_connection
        )

        self.assertEqual(None, result)

    def test_get_extended_key_usage_from_certificate(self):
        """
        Test that the ExtendedKeyUsage extension can be retrieved from a
        certificate.
        """
        extension = utils.get_extended_key_usage_from_certificate(
            self.certificate
        )

        self.assertIsInstance(extension, x509.ExtendedKeyUsage)
        self.assertIn(x509.ExtendedKeyUsageOID.CLIENT_AUTH, extension)

    def test_get_extended_key_usage_from_certificate_with_no_extension(self):
        """
        Test that the right value is returned when the ExtendedKeyUsage
        extension cannot be retrieved from a certificate.
        """
        extension = utils.get_extended_key_usage_from_certificate(
            self.certificate_no_extension
        )

        self.assertEqual(None, extension)

    def test_get_common_names_from_certificate(self):
        """
        Test that the common names can be retrieved from a certificate.
        """
        common_names = utils.get_common_names_from_certificate(
            self.certificate
        )

        self.assertEqual(["Jane Doe"], common_names)

    def test_get_common_names_from_certificate_no_common_names(self):
        """
        Test that the right value is returned when no common names can be
        retrieved from a certificate.
        """
        common_names = utils.get_common_names_from_certificate(
            self.certificate_no_name
        )

        self.assertEqual([], common_names)

    def test_get_client_identity_from_certificate(self):
        """
        Test that the common names from a certificate can be processed into a
        client identity.
        """
        result = utils.get_client_identity_from_certificate(self.certificate)

        self.assertEqual("Jane Doe", result)

    @mock.patch(
        'kmip.services.server.auth.utils.get_common_names_from_certificate'
    )
    def test_get_client_identity_from_certificate_multiple_names(self,
                                                                 mock_get):
        """
        Test that the a PermissionDenied error is raised if multiple possible
        client identities are discovered.
        """
        mock_get.return_value = ["John Doe", "Jane Doe"]

        args = ("test", )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Multiple client identities found.",
            utils.get_client_identity_from_certificate,
            *args
        )

    @mock.patch(
        'kmip.services.server.auth.utils.get_common_names_from_certificate'
    )
    def test_get_client_identity_from_certificate_no_names(self, mock_get):
        """
        Test that the a PermissionDenied error is raised if no possible client
        identities are discovered.
        """
        mock_get.return_value = []

        args = ("test", )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "The certificate does not define any subject common names. Client "
            "identity unavailable.",
            utils.get_client_identity_from_certificate,
            *args
        )
