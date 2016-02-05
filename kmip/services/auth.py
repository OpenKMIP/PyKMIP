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
import six
import ssl


@six.add_metaclass(abc.ABCMeta)
class AuthenticationSuite(object):
    """
    An authentication suite used to establish secure network connections.

    Acts as the base of the suite hierarchy.
    """

    @abc.abstractmethod
    def __init__(self):
        """
        Create an AuthenticationSuite object.
        """
        self._profile = []
        self._ciphers = ''

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
        return self._ciphers


class BasicAuthenticationSuite(AuthenticationSuite):
    """
    An authentication suite used to establish secure network connections.

    Supports TLS 1.0 and a subset of TLS 1.0 compliant cipher suites, defined
    in NIST 800-57, as defined by the KMIP specification.
    """

    def __init__(self):
        """
        Create a BasicAuthenticationSuite object.
        """
        super(BasicAuthenticationSuite, self).__init__()
        self._protocol = ssl.PROTOCOL_TLSv1
        self._ciphers = ':'.join((
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


class TLS12AuthenticationSuite(AuthenticationSuite):
    """
    An authentication suite used to establish secure network connections.

    Supports TLS 1.2 and a subset of TLS 1.2 compliant cipher suites, defined
    in NIST 800-57, as defined by the KMIP specification.
    """

    def __init__(self):
        """
        Create a TLS12AuthenticationSuite object.
        """
        super(TLS12AuthenticationSuite, self).__init__()
        self._protocol = ssl.PROTOCOL_TLSv1_2
        self._ciphers = ':'.join((
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
