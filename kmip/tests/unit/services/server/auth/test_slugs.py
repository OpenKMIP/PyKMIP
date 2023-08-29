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

import mock
import requests
import testtools

from kmip.core import exceptions
from kmip.services.server import auth


class TestSLUGSConnector(testtools.TestCase):
    """
    Test suite for the SLUGSConnector.
    """

    def setUp(self):
        super(TestSLUGSConnector, self).setUp()

    def tearDown(self):
        super(TestSLUGSConnector, self).tearDown()

    def test_init(self):
        """
        Test that a SLUGSConnector can be constructed without arguments.
        """
        auth.SLUGSConnector()

    def test_init_with_args(self):
        """
        Test that a SLUGSConnector can be constructed with arguments.
        """
        connector = auth.SLUGSConnector(url='http://127.0.0.1:8080/slugs/')

        self.assertEqual('http://127.0.0.1:8080/slugs/', connector.url)
        self.assertEqual(
            'http://127.0.0.1:8080/slugs/users/{}',
            connector.users_url
        )
        self.assertEqual(
            'http://127.0.0.1:8080/slugs/users/{}/groups',
            connector.groups_url
        )

    def test_url_formatting(self):
        """
        Test that a URL without a trailing slash is handled properly when used
        to set the URL of a SLUGSConnector.
        """
        connector = auth.SLUGSConnector(url="http://127.0.0.1:8080/slugs")

        self.assertEqual('http://127.0.0.1:8080/slugs/', connector.url)
        self.assertEqual(
            'http://127.0.0.1:8080/slugs/users/{}',
            connector.users_url
        )
        self.assertEqual(
            'http://127.0.0.1:8080/slugs/users/{}/groups',
            connector.groups_url
        )

        connector = auth.SLUGSConnector()

        self.assertEqual(None, connector.url)
        self.assertEqual(None, connector.users_url)
        self.assertEqual(None, connector.groups_url)

        connector.url = "http://127.0.0.1:8080/slugs"

        self.assertEqual('http://127.0.0.1:8080/slugs/', connector.url)
        self.assertEqual(
            'http://127.0.0.1:8080/slugs/users/{}',
            connector.users_url
        )
        self.assertEqual(
            'http://127.0.0.1:8080/slugs/users/{}/groups',
            connector.groups_url
        )

    def test_invalid_url(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the URL of a SLUGSConnector.
        """
        kwargs = {'url': 0}
        self.assertRaisesRegex(
            TypeError,
            "URL must be a string.",
            auth.SLUGSConnector,
            **kwargs
        )

        connector = auth.SLUGSConnector()
        args = (connector, "url", 0)
        self.assertRaisesRegex(
            TypeError,
            "URL must be a string.",
            setattr,
            *args
        )

    @mock.patch('requests.get')
    @mock.patch(
        'kmip.services.server.auth.utils.get_client_identity_from_certificate'
    )
    def test_authenticate(self, mock_get_client_identity, mock_request_get):
        """
        Test that a call to authenticate with the SLUGSConnector triggers the
        right utility and SLUGS API calls.
        """
        mock_get_client_identity.return_value = "John Doe"

        users_response = mock.MagicMock(requests.Response)
        users_response.status_code = 200
        groups_response = mock.MagicMock(requests.Response)
        groups_response.status_code = 200
        groups_response.json.return_value = {'groups': ['Group A', 'Group B']}

        mock_request_get.side_effect = [users_response, groups_response]

        connector = auth.SLUGSConnector(
            url="http://127.0.0.1:8080/test/slugs/"
        )
        result = connector.authenticate("test")

        mock_get_client_identity.assert_called_once_with("test")
        mock_request_get.assert_any_call(
            "http://127.0.0.1:8080/test/slugs/users/John Doe", timeout=10
        )
        mock_request_get.assert_any_call(
            "http://127.0.0.1:8080/test/slugs/users/John Doe/groups", timeout=10
        )
        self.assertEqual(('John Doe', ['Group A', 'Group B']), result)

    @mock.patch('requests.get')
    @mock.patch(
        'kmip.services.server.auth.utils.get_client_identity_from_certificate'
    )
    def test_authenticate_with_url_unset(self,
                                         mock_get_client_identity,
                                         mock_request_get):
        """
        Test that a ConfigurationError is raised when attempting to
        authenticate with an unset URL.
        """
        connector = auth.SLUGSConnector()

        args = ("test", )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            "The SLUGS URL must be specified.",
            connector.authenticate,
            *args
        )

    @mock.patch('requests.get')
    @mock.patch(
        'kmip.services.server.auth.utils.get_client_identity_from_certificate'
    )
    def test_authenticate_with_connection_failure(self,
                                                  mock_get_client_identity,
                                                  mock_request_get):
        """
        Test that a ConfigurationError is raised when attempting to
        authenticate with an invalid URL.
        """
        mock_get_client_identity.return_value = "John Doe"
        mock_request_get.side_effect = [requests.exceptions.ConnectionError()]

        connector = auth.SLUGSConnector(
            url="http://127.0.0.1:8080/test/slugs/"
        )
        args = ("test", )
        self.assertRaisesRegex(
            exceptions.ConfigurationError,
            "A connection could not be established using the SLUGS URL.",
            connector.authenticate,
            *args
        )

    @mock.patch('requests.get')
    @mock.patch(
        'kmip.services.server.auth.utils.get_client_identity_from_certificate'
    )
    def test_authenticate_with_users_failure(self,
                                             mock_get_client_identity,
                                             mock_request_get):
        """
        Test that a PermissionDenied error is raised when an invalid user ID
        is used to query SLUGS.
        """
        mock_get_client_identity.return_value = "John Doe"

        users_response = mock.MagicMock(requests.Response)
        users_response.status_code = 404

        mock_request_get.return_value = users_response

        connector = auth.SLUGSConnector(
            url="http://127.0.0.1:8080/test/slugs/"
        )
        args = ("test", )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Unrecognized user ID: John Doe",
            connector.authenticate,
            *args
        )

    @mock.patch('requests.get')
    @mock.patch(
        'kmip.services.server.auth.utils.get_client_identity_from_certificate'
    )
    def test_authenticate_with_groups_failure(self,
                                              mock_get_client_identity,
                                              mock_request_get):
        """
        Test that a PermissionDenied error is raised when a groups request to
        SLUGS fails.
        """
        mock_get_client_identity.return_value = "John Doe"

        users_response = mock.MagicMock(requests.Response)
        users_response.status_code = 200
        groups_response = mock.MagicMock(requests.Response)
        groups_response.status_code = 404

        mock_request_get.side_effect = [users_response, groups_response]

        connector = auth.SLUGSConnector(
            url="http://127.0.0.1:8080/test/slugs/"
        )
        args = ("test", )
        self.assertRaisesRegex(
            exceptions.PermissionDenied,
            "Group information could not be retrieved for user ID: John Doe",
            connector.authenticate,
            *args
        )
