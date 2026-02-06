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

import shutil
import re
import tempfile
import testtools

from kmip.core import enums
from kmip.core import policy

class TestPolicy(testtools.TestCase):

    def setUp(self):
        super(TestPolicy, self).setUp()

        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)

    def tearDown(self):
        super(TestPolicy, self).tearDown()

    def test_parse_policy(self):
        """
        Test that parsing a text-based policy works correctly.
        """
        object_policy = {"CERTIFICATE": {"LOCATE": "ALLOW_ALL"}}
        observed = policy.parse_policy(object_policy)

        expected = {
            enums.ObjectType.CERTIFICATE: {
                enums.Operation.LOCATE: enums.Policy.ALLOW_ALL
            }
        }

        self.assertEqual(expected, observed)

    def test_parse_policy_with_bad_object_type(self):
        """
        Test that policy parsing correctly handles an invalid object type
        string.
        """
        object_policy = {"INVALID": {"LOCATE": "ALLOW_ALL"}}

        args = (object_policy, )
        regex = "'INVALID' is not a valid ObjectType value."
        self.assertRaisesRegex(
            ValueError,
            regex,
            policy.parse_policy,
            *args
        )

    def test_parse_policy_with_bad_operation(self):
        """
        Test that policy parsing correctly handles an invalid operation string.
        """
        object_policy = {"CERTIFICATE": {"INVALID": "ALLOW_ALL"}}

        args = (object_policy, )
        regex = "'INVALID' is not a valid Operation value."
        self.assertRaisesRegex(
            ValueError,
            regex,
            policy.parse_policy,
            *args
        )

    def test_parse_policy_with_bad_permission(self):
        """
        Test that policy parsing correctly handles an invalid permission
        string.
        """
        object_policy = {"CERTIFICATE": {"LOCATE": "INVALID"}}

        args = (object_policy, )
        regex = "'INVALID' is not a valid Policy value."
        self.assertRaisesRegex(
            ValueError,
            regex,
            policy.parse_policy,
            *args
        )

    def test_read_policy_from_file(self):
        """
        Test that reading a policy file works correctly.
        """
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": {'
                '"groups": {"group_A": {"SPLIT_KEY": {"GET": "ALLOW_ALL"}}}, '
                '"preset": {"SPLIT_KEY": {"GET": "ALLOW_ALL"}}}'
                '}'
            )

        policies = policy.read_policy_from_file(policy_file.name)

        self.assertEqual(1, len(policies))
        self.assertIn('test', policies.keys())

        expected = {
            'groups': {
                'group_A': {
                    enums.ObjectType.SPLIT_KEY: {
                        enums.Operation.GET: enums.Policy.ALLOW_ALL
                    }
                }
            },
            'preset': {
                enums.ObjectType.SPLIT_KEY: {
                    enums.Operation.GET: enums.Policy.ALLOW_ALL
                }
            }
        }

        self.assertEqual(expected, policies.get('test'))

    def test_read_policy_from_file_groups_only(self):
        """
        Test that reading a policy file with only a groups section works
        correctly.
        """
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": '
                '{"groups": {"group_A": {"SPLIT_KEY": {"GET": "ALLOW_ALL"}}}}}'
            )

        policies = policy.read_policy_from_file(policy_file.name)

        self.assertEqual(1, len(policies))
        self.assertIn('test', policies.keys())

        expected = {
            'groups': {
                'group_A': {
                    enums.ObjectType.SPLIT_KEY: {
                        enums.Operation.GET: enums.Policy.ALLOW_ALL
                    }
                }
            }
        }

        self.assertEqual(expected, policies.get('test'))

    def test_read_policy_from_file_default_only(self):
        """
        Test that reading a policy file with only a preset section works
        correctly.
        """
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": '
                '{"preset": {"SPLIT_KEY": {"GET": "ALLOW_ALL"}}}}'
            )

        policies = policy.read_policy_from_file(policy_file.name)

        self.assertEqual(1, len(policies))
        self.assertIn('test', policies.keys())

        expected = {
            'preset': {
                enums.ObjectType.SPLIT_KEY: {
                    enums.Operation.GET: enums.Policy.ALLOW_ALL
                }
            }
        }

        self.assertEqual(expected, policies.get('test'))

    def test_read_policy_from_file_invalid_section(self):
        """
        Test that reading a policy file with an invalid section generates
        the right error.
        """
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": {'
                '"invalid": {"group_A": {"SPLIT_KEY": {"GET": "ALLOW_ALL"}}}}}'
            )

        args = (policy_file.name, )
        regex = "Policy 'test' contains an invalid section named: invalid"
        self.assertRaisesRegex(
            ValueError,
            regex,
            policy.read_policy_from_file,
            *args
        )

    def test_read_policy_from_file_legacy(self):
        """
        Test that reading a legacy policy file works correctly.

        Note: legacy policy file support may be removed in the future.
        """
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": {"CERTIFICATE": {"LOCATE": "ALLOW_ALL"}}}'
            )

        policies = policy.read_policy_from_file(policy_file.name)

        self.assertEqual(1, len(policies))
        self.assertIn('test', policies.keys())

        expected = {
            'preset': {
                enums.ObjectType.CERTIFICATE: {
                    enums.Operation.LOCATE: enums.Policy.ALLOW_ALL
                }
            }
        }

        self.assertEqual(expected, policies.get('test'))

    def test_read_policy_from_file_empty(self):
        """
        Test that reading an empty policy file generates the right error.
        """
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        policy_file.close()
        with open(policy_file.name, 'w') as f:
            f.write('')

        args = (policy_file.name, )
        regex = "Loading the policy file '{}' generated a JSON error:".format(
            re.escape(policy_file.name)
        )
        self.assertRaisesRegex(
            ValueError,
            regex,
            policy.read_policy_from_file,
            *args
        )

    def test_read_policy_from_file_empty_policy(self):
        """
        Test that reading a file with an empty policy is handled correctly.
        """
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        policy_file.close()
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": {}}'
            )

        policies = policy.read_policy_from_file(policy_file.name)

        self.assertEqual(0, len(policies))
