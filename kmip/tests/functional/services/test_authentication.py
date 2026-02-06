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

import os
import pytest

import testtools
import time

from kmip.core import enums
from kmip.pie import client
from kmip.pie import exceptions
from kmip.pie import objects

@pytest.mark.usefixtures("config_file")
class TestSLUGSAuthenticationAndAccessControl(testtools.TestCase):

    def setUp(self):
        super(TestSLUGSAuthenticationAndAccessControl, self).setUp()

        self.client_john_doe = client.ProxyKmipClient(
            config='john_doe',
            config_file=self.config_file
        )
        self.client_jane_doe = client.ProxyKmipClient(
            config='jane_doe',
            config_file=self.config_file
        )
        self.client_john_smith = client.ProxyKmipClient(
            config='john_smith',
            config_file=self.config_file
        )
        self.client_jane_smith = client.ProxyKmipClient(
            config='jane_smith',
            config_file=self.config_file
        )

    def tearDown(self):
        super(TestSLUGSAuthenticationAndAccessControl, self).tearDown()

    def test_group_level_access_control(self):
        """
        Test that:
        1. a user in Group A can create and retrieve a symmetric key
        2. a user in Group B can also retrieve the same symmetric key
        3. a user in both Groups can also retrieve the same symmetric key
        4. a user in Group B cannot destroy the same symmetric key, and
        5. a user in Group A can destroy the same symmetric key.
        """
        with self.client_john_doe as c:
            uid = c.create(
                enums.CryptographicAlgorithm.AES,
                256,
                operation_policy_name="policy_1"
            )
            self.assertIsInstance(uid, str)

            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

        with self.client_jane_doe as c:
            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

        with self.client_john_smith as c:
            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

            self.assertRaises(exceptions.KmipOperationFailure, c.destroy, uid)

        with self.client_john_doe as c:
            c.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, c.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, c.destroy, uid)

    def test_policy_live_loading(self):
        """
        Test that:
        1. a user in Group A can create and retrieve a symmetric key
        2. a user in Group B can also retrieve the same symmetric key
        3. a user in Group B cannot destroy the same symmetric key
        4. a policy is uploaded if created after server start up
        5. a user in Group A cannot retrieve the same symmetric key, and
        6. a user in Group B can destroy the same symmetric key.
        """
        with self.client_john_doe as c:
            uid = c.create(
                enums.CryptographicAlgorithm.AES,
                256,
                operation_policy_name="policy_1"
            )
            self.assertIsInstance(uid, str)

            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

        with self.client_john_smith as c:
            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

            self.assertRaises(exceptions.KmipOperationFailure, c.destroy, uid)

        with open("/tmp/pykmip/policies/policy_overwrite.json", "w") as f:
            f.write('{\n')
            f.write('  "policy_1": {\n')
            f.write('    "groups": {\n')
            f.write('      "Group A": {\n')
            f.write('        "SYMMETRIC_KEY": {\n')
            f.write('          "GET": "DISALLOW_ALL",\n')
            f.write('          "DESTROY": "DISALLOW_ALL"\n')
            f.write('        }\n')
            f.write('      },\n')
            f.write('      "Group B": {\n')
            f.write('        "SYMMETRIC_KEY": {\n')
            f.write('          "GET": "ALLOW_ALL",\n')
            f.write('          "DESTROY": "ALLOW_ALL"\n')
            f.write('        }\n')
            f.write('      }\n')
            f.write('    }\n')
            f.write('  }\n')
            f.write('}\n')
        time.sleep(1)

        with self.client_john_doe as c:
            self.assertRaises(exceptions.KmipOperationFailure, c.get, uid)
            self.assertRaises(exceptions.KmipOperationFailure, c.destroy, uid)

        with self.client_john_smith as c:
            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

            c.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, c.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, c.destroy, uid)

        os.remove("/tmp/pykmip/policies/policy_overwrite.json")
        time.sleep(1)

    def test_policy_caching(self):
        """
        Test that:
        1. a user in Group A can create and retrieve a symmetric key
        2. a policy is uploaded if created after server start up
        3. a user in Group A cannot retrieve or destroy the same symmetric key
        4. the original policy is restored after the new policy is removed, and
        5. a user in Group A can retrieve and destroy the same symmetric key.
        """
        with self.client_john_doe as c:
            uid = c.create(
                enums.CryptographicAlgorithm.AES,
                256,
                operation_policy_name="policy_1"
            )
            self.assertIsInstance(uid, str)

            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

            with open("/tmp/pykmip/policies/policy_caching.json", "w") as f:
                f.write('{\n')
                f.write('  "policy_1": {\n')
                f.write('    "groups": {\n')
                f.write('      "Group A": {\n')
                f.write('        "SYMMETRIC_KEY": {\n')
                f.write('          "GET": "DISALLOW_ALL",\n')
                f.write('          "DESTROY": "DISALLOW_ALL"\n')
                f.write('        }\n')
                f.write('      }\n')
                f.write('    }\n')
                f.write('  }\n')
                f.write('}\n')
            time.sleep(1)

            self.assertRaises(exceptions.KmipOperationFailure, c.get, uid)
            self.assertRaises(exceptions.KmipOperationFailure, c.destroy, uid)

            os.remove("/tmp/pykmip/policies/policy_caching.json")
            time.sleep(1)

            key = c.get(uid)
            self.assertIsInstance(key, objects.SymmetricKey)
            self.assertEqual(
                key.cryptographic_algorithm,
                enums.CryptographicAlgorithm.AES)
            self.assertEqual(key.cryptographic_length, 256)

            c.destroy(uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, c.get, uid)
            self.assertRaises(
                exceptions.KmipOperationFailure, c.destroy, uid)

    def test_authenticating_unrecognized_user(self):
        """
        Test that an unrecognized user is blocked from submitting a request.
        """
        with open("/tmp/slugs/user_group_mapping.csv", "w") as f:
            f.write('Jane Doe,Group A\n')
            f.write('Jane Doe,Group B\n')
            f.write('John Smith,Group B\n')
        time.sleep(1)

        args = (enums.CryptographicAlgorithm.AES, 256)
        kwargs = {'operation_policy_name': 'policy_1'}
        with self.client_john_doe as c:
            self.assertRaises(
                exceptions.KmipOperationFailure,
                c.create,
                *args,
                **kwargs
            )

        with open("/tmp/slugs/user_group_mapping.csv", "w") as f:
            f.write('John Doe,Group A\n')
            f.write('Jane Doe,Group A\n')
            f.write('Jane Doe,Group B\n')
            f.write('John Smith,Group B\n')
        time.sleep(1)
