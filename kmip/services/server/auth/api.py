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

import abc

class AuthAPI(metaclass=abc.ABCMeta):
    """
    The base class for an authentication API connector.
    """

    @abc.abstractmethod
    def authenticate(self,
                     connection_certificate=None,
                     connection_info=None,
                     request_credentials=None):
        """
        Query the configured authentication service with the given credentials.

        Args:
            connection_certificate (cryptography.x509.Certificate): An X.509
                certificate object obtained from the connection being
                authenticated. Optional, defaults to None.
            connection_info (tuple): A tuple of information pertaining to the
                connection being authenticated, including the source IP address
                and a timestamp (e.g., ('127.0.0.1', 1519759267.467451)).
                Optional, defaults to None.
            request_credentials (list): A list of KMIP Credential structures
                containing credential information to use for authentication.
                Optional, defaults to None.
        """
