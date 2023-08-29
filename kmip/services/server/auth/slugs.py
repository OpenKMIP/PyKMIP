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

import requests
import six

from kmip.core import exceptions
from kmip.services.server.auth import api
from kmip.services.server.auth import utils


class SLUGSConnector(api.AuthAPI):
    """
    An authentication API connector for a SLUGS service.
    """

    def __init__(self, url=None):
        """
        Construct a SLUGSConnector.

        Args:
            url (string): The base URL for the remote SLUGS instance. Optional,
                defaults to None. Required for authentication.
        """
        self._url = None
        self.users_url = None
        self.groups_url = None

        self.url = url

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        if value is None:
            self._url = None
            self.users_url = None
            self.groups_url = None
        elif isinstance(value, six.string_types):
            self._url = value
            if not self._url.endswith("/"):
                self._url += "/"
            self.users_url = self._url + "users/{}"
            self.groups_url = self.users_url + "/groups"
        else:
            raise TypeError("URL must be a string.")

    def authenticate(self,
                     connection_certificate=None,
                     connection_info=None,
                     request_credentials=None):
        """
        Query the configured SLUGS service with the provided credentials.

        Args:
            connection_certificate (cryptography.x509.Certificate): An X.509
                certificate object obtained from the connection being
                authenticated. Required for SLUGS authentication.
            connection_info (tuple): A tuple of information pertaining to the
                connection being authenticated, including the source IP address
                and a timestamp (e.g., ('127.0.0.1', 1519759267.467451)).
                Optional, defaults to None. Ignored for SLUGS authentication.
            request_credentials (list): A list of KMIP Credential structures
                containing credential information to use for authentication.
                Optional, defaults to None. Ignored for SLUGS authentication.
        """
        if (self.users_url is None) or (self.groups_url is None):
            raise exceptions.ConfigurationError(
                "The SLUGS URL must be specified."
            )

        user_id = utils.get_client_identity_from_certificate(
            connection_certificate
        )

        try:
            response = requests.get(self.users_url.format(user_id), timeout=10)
        except Exception:
            raise exceptions.ConfigurationError(
                "A connection could not be established using the SLUGS URL."
            )
        if response.status_code == 404:
            raise exceptions.PermissionDenied(
                "Unrecognized user ID: {}".format(user_id)
            )

        response = requests.get(self.groups_url.format(user_id), timeout=10)
        if response.status_code == 404:
            raise exceptions.PermissionDenied(
                "Group information could not be retrieved for user ID: "
                "{}".format(user_id)
            )

        return user_id, response.json().get('groups')
