# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

import pytest
import ssl
import testtools

from kmip.services import auth

class TestBasicAuthenticationSuite(testtools.TestCase):
    """
    A test suite for the BasicAuthenticationSuite.
    """

    def setUp(self):
        super(TestBasicAuthenticationSuite, self).setUp()

    def tearDown(self):
        super(TestBasicAuthenticationSuite, self).tearDown()

    def test_init(self):
        auth.BasicAuthenticationSuite()

    def test_protocol(self):
        suite = auth.BasicAuthenticationSuite()
        protocol = suite.protocol

        self.assertIsInstance(protocol, int)
        self.assertEqual(ssl.PROTOCOL_TLSv1, suite.protocol)

    def test_ciphers(self):
        suite = auth.BasicAuthenticationSuite()
        ciphers = suite.ciphers

        self.assertIsInstance(ciphers, str)

        cipher_string = ':'.join((
            'AES128-SHA',
            'DES-CBC3-SHA',
            'AES256-SHA',
            'DHE-DSS-DES-CBC3-SHA',
            'DHE-RSA-DES-CBC3-SHA',
            'DH-DSS-AES128-SHA',
            'DH-RSA-AES128-SHA',
            'DHE-DSS-AES128-SHA',
            'DHE-RSA-AES128-SHA',
            'DH-RSA-AES256-SHA',
            'DHE-DSS-AES256-SHA',
            'DHE-RSA-AES256-SHA',
        ))

        self.assertEqual(cipher_string, ciphers)

    def test_custom_ciphers(self):
        """
        Test that providing a custom list of cipher suites yields the right
        cipher string for the Basic auth suite.
        """
        suite = auth.BasicAuthenticationSuite(
            [
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
                'DHE-DSS-AES256-SHA',
                'DHE-RSA-AES256-SHA'
            ]
        )
        ciphers = suite.ciphers

        self.assertIsInstance(ciphers, str)
        suites = ciphers.split(':')
        self.assertEqual(4, len(suites))
        self.assertIn('AES128-SHA', suites)
        self.assertIn('AES256-SHA', suites)
        self.assertIn('DHE-DSS-AES256-SHA', suites)
        self.assertIn('DHE-RSA-AES256-SHA', suites)

    def test_custom_ciphers_empty(self):
        """
        Test that providing a custom list of cipher suites that ultimately
        yields an empty suite list causes the default cipher suite list to
        be provided instead.
        """
        suite = auth.BasicAuthenticationSuite(
            [
                'TLS_RSA_WITH_AES_256_CBC_SHA256'
            ]
        )
        ciphers = suite.ciphers

        self.assertIsInstance(ciphers, str)
        suites = ciphers.split(':')
        self.assertEqual(12, len(suites))
        self.assertIn('AES128-SHA', suites)
        self.assertIn('DES-CBC3-SHA', suites)
        self.assertIn('AES256-SHA', suites)
        self.assertIn('DHE-DSS-DES-CBC3-SHA', suites)
        self.assertIn('DHE-RSA-DES-CBC3-SHA', suites)
        self.assertIn('DH-DSS-AES128-SHA', suites)
        self.assertIn('DH-RSA-AES128-SHA', suites)
        self.assertIn('DHE-DSS-AES128-SHA', suites)
        self.assertIn('DHE-RSA-AES128-SHA', suites)
        self.assertIn('DH-RSA-AES256-SHA', suites)
        self.assertIn('DHE-DSS-AES256-SHA', suites)
        self.assertIn('DHE-RSA-AES256-SHA', suites)

@pytest.mark.skipif(not hasattr(ssl, 'PROTOCOL_TLSv1_2'),
                    reason="Requires ssl.PROTOCOL_TLSv1_2")
class TestTLS12AuthenticationSuite(testtools.TestCase):
    """
    A test suite for the TLS12AuthenticationSuite.
    """

    def setUp(self):
        super(TestTLS12AuthenticationSuite, self).setUp()

    def tearDown(self):
        super(TestTLS12AuthenticationSuite, self).tearDown()

    def test_init(self):
        auth.TLS12AuthenticationSuite()

    def test_protocol(self):
        suite = auth.TLS12AuthenticationSuite()
        protocol = suite.protocol

        self.assertIsInstance(protocol, int)
        self.assertEqual(ssl.PROTOCOL_TLSv1_2, suite.protocol)

    def test_ciphers(self):
        suite = auth.TLS12AuthenticationSuite()
        ciphers = suite.ciphers

        self.assertIsInstance(ciphers, str)

        cipher_string = ':'.join((
            'AES128-SHA256',
            'AES256-SHA256',
            'DH-DSS-AES256-SHA256',
            'DH-DSS-AES128-SHA256',
            'DH-RSA-AES128-SHA256',
            'DHE-DSS-AES128-SHA256',
            'DHE-RSA-AES128-SHA256',
            'DH-DSS-AES256-SHA256',
            'DH-RSA-AES256-SHA256',
            'DHE-DSS-AES256-SHA256',
            'DHE-RSA-AES256-SHA256',
            'ECDH-ECDSA-AES128-SHA256',
            'ECDH-ECDSA-AES256-SHA256',
            'ECDHE-ECDSA-AES128-SHA256',
            'ECDHE-ECDSA-AES256-SHA384',
            'ECDH-RSA-AES128-SHA256',
            'ECDH-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-SHA256',
            'ECDHE-ECDSA-AES256-SHA384',
        ))

        self.assertEqual(cipher_string, ciphers)

    def test_custom_ciphers(self):
        """
        Test that providing a custom list of cipher suites yields the right
        cipher string.
        """
        suite = auth.TLS12AuthenticationSuite(
            [
                'TLS_RSA_WITH_AES_256_CBC_SHA256',
                'TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
                'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
                'DHE-DSS-AES256-SHA',
                'DHE-RSA-AES256-SHA'
            ]
        )
        ciphers = suite.ciphers

        self.assertIsInstance(ciphers, str)
        suites = ciphers.split(':')
        self.assertEqual(1, len(suites))
        self.assertIn('AES256-SHA256', suites)

    def test_custom_ciphers_empty(self):
        """
        Test that providing a custom list of cipher suites that ultimately
        yields an empty suite list causes the default cipher suite list to
        be provided instead.
        """
        suite = auth.TLS12AuthenticationSuite(
            [
                'TLS_RSA_WITH_AES_256_CBC_SHA'
            ]
        )
        ciphers = suite.ciphers

        self.assertIsInstance(ciphers, str)
        suites = ciphers.split(':')
        self.assertEqual(23, len(suites))
        self.assertIn('AES128-SHA256', suites)
        self.assertIn('AES256-SHA256', suites)
        self.assertIn('DH-DSS-AES256-SHA256', suites)
        self.assertIn('DH-DSS-AES128-SHA256', suites)
        self.assertIn('DH-RSA-AES128-SHA256', suites)
        self.assertIn('DHE-DSS-AES128-SHA256', suites)
        self.assertIn('DHE-RSA-AES128-SHA256', suites)
        self.assertIn('DH-DSS-AES256-SHA256', suites)
        self.assertIn('DH-RSA-AES256-SHA256', suites)
        self.assertIn('DHE-DSS-AES256-SHA256', suites)
        self.assertIn('DHE-RSA-AES256-SHA256', suites)
        self.assertIn('ECDH-ECDSA-AES128-SHA256', suites)
        self.assertIn('ECDH-ECDSA-AES256-SHA256', suites)
        self.assertIn('ECDHE-ECDSA-AES128-SHA256', suites)
        self.assertIn('ECDHE-ECDSA-AES256-SHA384', suites)
        self.assertIn('ECDH-RSA-AES128-SHA256', suites)
        self.assertIn('ECDH-RSA-AES256-SHA384', suites)
        self.assertIn('ECDHE-RSA-AES128-SHA256', suites)
        self.assertIn('ECDHE-RSA-AES256-SHA384', suites)
        self.assertIn('ECDHE-ECDSA-AES128-GCM-SHA256', suites)
        self.assertIn('ECDHE-ECDSA-AES256-GCM-SHA384', suites)
        self.assertIn('ECDHE-ECDSA-AES128-SHA256', suites)
        self.assertIn('ECDHE-ECDSA-AES256-SHA384', suites)
