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

import abc

import ssl

class AuthenticationSuite(metaclass=abc.ABCMeta):
    """
    An authentication suite used to establish secure network connections.

    Acts as the base of the suite hierarchy.
    """

    # OpenSSL cipher suites
    # Explicitly listed suites for Basic and TLSv1.2 authentication for KMIP
    # profiles.
    #
    # Obtained from:
    #     https://www.openssl.org/docs/man1.1.0/apps/ciphers.html
    #     https://www.openssl.org/docs/man1.0.2/apps/ciphers.html
    openssl_cipher_suite_map = {
        # TLS v1.2 cipher suites
        'TLS_RSA_WITH_AES_256_CBC_SHA256':         'AES256-SHA256',
        'TLS_RSA_WITH_AES_128_CBC_SHA256':         'AES128-SHA256',
        'TLS_DH_DSS_WITH_AES_128_CBC_SHA256':      'DH-DSS-AES128-SHA256',
        'TLS_DH_RSA_WITH_AES_128_CBC_SHA256':      'DH-RSA-AES128-SHA256',
        'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256':     'DHE-DSS-AES128-SHA256',
        'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256':     'DHE-RSA-AES128-SHA256',
        'TLS_DH_DSS_WITH_AES_256_CBC_SHA256':      'DH-DSS-AES256-SHA256',
        'TLS_DH_RSA_WITH_AES_256_CBC_SHA256':      'DH-RSA-AES256-SHA256',
        'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256':     'DHE-DSS-AES256-SHA256',
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256':     'DHE-RSA-AES256-SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256': 'ECDHE-ECDSA-AES128-SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384': 'ECDHE-ECDSA-AES256-SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256':   'ECDHE-RSA-AES128-SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384':   'ECDHE-RSA-AES256-SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256':
            'ECDHE-ECDSA-AES128-GCM-SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384':
            'ECDHE-ECDSA-AES256-GCM-SHA384',
        'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256':  'ECDH-ECDSA-AES128-SHA256',
        'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384':  'ECDH-ECDSA-AES256-SHA384',
        'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256':    'ECDH-RSA-AES128-SHA256',
        'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384':    'ECDH-RSA-AES256-SHA384',

        # AES ciphersuites from RFC3268, extending TLS v1.0
        'TLS_RSA_WITH_AES_128_CBC_SHA':     'AES128-SHA',
        'TLS_RSA_WITH_AES_256_CBC_SHA':     'AES256-SHA',
        'TLS_DH_DSS_WITH_AES_128_CBC_SHA':  'DH-DSS-AES128-SHA',
        'TLS_DH_RSA_WITH_AES_128_CBC_SHA':  'DH-RSA-AES128-SHA',
        'TLS_DHE_DSS_WITH_AES_128_CBC_SHA': 'DHE-DSS-AES128-SHA',
        'TLS_DHE_RSA_WITH_AES_128_CBC_SHA': 'DHE-RSA-AES128-SHA',
        'TLS_DH_DSS_WITH_AES_256_CBC_SHA':  'DH-DSS-AES256-SHA',
        'TLS_DH_RSA_WITH_AES_256_CBC_SHA':  'DH-RSA-AES256-SHA',
        'TLS_DHE_DSS_WITH_AES_256_CBC_SHA': 'DHE-DSS-AES256-SHA',
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA': 'DHE-RSA-AES256-SHA',

        # Elliptic curve cipher suites.
        'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA': 'ECDHE-ECDSA-AES128-SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA':   'ECDHE-RSA-AES128-SHA',

        # Pre shared keying (PSK) cipheruites
        'TLS_PSK_WITH_AES_128_CBC_SHA': 'PSK-AES128-CBC-SHA',
        'TLS_PSK_WITH_AES_256_CBC_SHA': 'PSK-AES256-CBC-SHA',

        # No OpenSSL support
        'TLS_DHE_PSK_WITH_AES_128_CBC_SHA': None,
        'TLS_DHE_PSK_WITH_AES_256_CBC_SHA': None,
        'TLS_RSA_PSK_WITH_AES_128_CBC_SHA': None,
        'TLS_RSA_PSK_WITH_AES_256_CBC_SHA': None
    }

    _default_cipher_suites = []

    @abc.abstractmethod
    def __init__(self, cipher_suites=None):
        """
        Create an AuthenticationSuite object.

        Args:
            cipher_suites (list): A list of strings representing the names of
                cipher suites to use. Overrides the default set of cipher
                suites. Optional, defaults to None.
        """
        self._custom_suites = []

        # Compose a unique list of custom cipher suites if any were provided.
        # Translate each suite name into its corresponding OpenSSL suite name,
        # allowing for both specification and OpenSSL suite names in the
        # provided list.
        if cipher_suites:
            for cipher_suite in cipher_suites:
                if cipher_suite in self.openssl_cipher_suite_map.keys():
                    suite = self.openssl_cipher_suite_map.get(cipher_suite)
                    if suite:
                        self._custom_suites.append(suite)
                elif cipher_suite in self.openssl_cipher_suite_map.values():
                    if cipher_suite:
                        self._custom_suites.append(cipher_suite)
            self._custom_suites = list(set(self._custom_suites))

        # Filter the custom suites to only include those from the default
        # cipher suite list (provided for each subclass authentication suite).
        # If no custom suites were specified, use the default cipher suites.
        suites = []
        if self._custom_suites:
            for suite in self._custom_suites:
                if suite in self._default_cipher_suites:
                    suites.append(suite)
        else:
            suites = self._default_cipher_suites

        self._cipher_suites = ':'.join(suites)
        if self._cipher_suites == '':
            self._cipher_suites = ':'.join(self._default_cipher_suites)

    @property
    def protocol(self):
        """
        Get the authentication suite protocol.

        Returns:
            int: The value of the ssl.PROTOCOL_* setting for this suite.
        """
        return self._protocol

    @property
    def ciphers(self):
        """
        Get the authentication suite cipher string.

        Returns:
            string: A colon delimited string listing the valid ciphers for
                the suite protocol.
        """
        return self._cipher_suites

class BasicAuthenticationSuite(AuthenticationSuite):
    """
    An authentication suite used to establish secure network connections.

    Supports TLS 1.0 and a subset of TLS 1.0 compliant cipher suites, defined
    in NIST 800-57, as defined by the KMIP specification.
    """

    _default_cipher_suites = [
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
        'DHE-RSA-AES256-SHA'
    ]

    def __init__(self, cipher_suites=None):
        """
        Create a BasicAuthenticationSuite object.

        Args:
            cipher_suites (list): A list of strings representing the names of
                cipher suites to use. Overrides the default set of cipher
                suites. Optional, defaults to None.
        """
        super(BasicAuthenticationSuite, self).__init__(cipher_suites)
        self._protocol = ssl.PROTOCOL_TLSv1

class TLS12AuthenticationSuite(AuthenticationSuite):
    """
    An authentication suite used to establish secure network connections.

    Supports TLS 1.2 and a subset of TLS 1.2 compliant cipher suites, defined
    in NIST 800-57, as defined by the KMIP specification.
    """

    _default_cipher_suites = [
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
        'ECDHE-ECDSA-AES256-SHA384'
    ]

    def __init__(self, cipher_suites=None):
        """
        Create a TLS12AuthenticationSuite object.

        Args:
            cipher_suites (list): A list of strings representing the names of
                cipher suites to use. Overrides the default set of cipher
                suites. Optional, defaults to None.
        """
        super(TLS12AuthenticationSuite, self).__init__(cipher_suites)
        self._protocol = ssl.PROTOCOL_TLSv1_2
