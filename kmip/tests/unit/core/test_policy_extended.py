# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
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
import re
import tempfile

import testtools

from kmip.core import enums
from kmip.core import policy


class TestPolicyExtended(testtools.TestCase):
    def setUp(self):
        super(TestPolicyExtended, self).setUp()
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(self._cleanup_temp_dir)

    def _cleanup_temp_dir(self):
        for root, _, files in os.walk(self.temp_dir):
            for filename in files:
                os.remove(os.path.join(root, filename))
        os.rmdir(self.temp_dir)

    def _write_policy(self, content):
        path = os.path.join(self.temp_dir, "policy.json")
        with open(path, "w") as handle:
            handle.write(content)
        return path

    def test_parse_policy_from_file(self):
        policy_path = self._write_policy(
            '{"default": {"preset": {"CERTIFICATE": {"LOCATE": "ALLOW_ALL"}}}}'
        )
        policies = policy.read_policy_from_file(policy_path)
        self.assertIn("default", policies)
        preset = policies["default"]["preset"]
        self.assertEqual(
            enums.Policy.ALLOW_ALL,
            preset[enums.ObjectType.CERTIFICATE][enums.Operation.LOCATE]
        )

    def test_parse_policy_invalid_json(self):
        policy_path = self._write_policy("{")
        error = "Loading the policy file '{}' generated a JSON error:".format(
            policy_path
        )
        self.assertRaisesRegex(
            ValueError,
            re.escape(error),
            policy.read_policy_from_file,
            policy_path
        )

    def test_policy_default_permissions(self):
        default = policy.policies["default"]["preset"]
        self.assertEqual(
            enums.Policy.ALLOW_ALL,
            default[enums.ObjectType.CERTIFICATE][enums.Operation.LOCATE]
        )

    def test_policy_custom_permissions(self):
        public = policy.policies["public"]["preset"]
        self.assertEqual(
            enums.Policy.DISALLOW_ALL,
            public[enums.ObjectType.TEMPLATE][enums.Operation.ADD_ATTRIBUTE]
        )

    def test_policy_check_allowed(self):
        default = policy.policies["default"]["preset"]
        allowed = default[enums.ObjectType.CERTIFICATE][enums.Operation.GET]
        self.assertEqual(enums.Policy.ALLOW_ALL, allowed)

    def test_policy_check_denied(self):
        public = policy.policies["public"]["preset"]
        denied = public[enums.ObjectType.TEMPLATE][enums.Operation.DESTROY]
        self.assertEqual(enums.Policy.DISALLOW_ALL, denied)

    def test_policy_unknown_object_type(self):
        object_policy = {"INVALID": {"LOCATE": "ALLOW_ALL"}}
        self.assertRaises(ValueError, policy.parse_policy, object_policy)

    def test_policy_unknown_operation(self):
        object_policy = {"CERTIFICATE": {"INVALID": "ALLOW_ALL"}}
        self.assertRaises(ValueError, policy.parse_policy, object_policy)
