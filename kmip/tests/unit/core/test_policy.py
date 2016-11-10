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

    def test_read_policy_from_file(self):
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

        test_policy = {
            enums.ObjectType.CERTIFICATE: {
                enums.Operation.LOCATE: enums.Policy.ALLOW_ALL
            }
        }

        self.assertEqual(test_policy, policies.get('test'))

    def test_read_policy_from_file_empty(self):
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write('')

        args = (policy_file.name, )
        regex = "An error occurred while attempting to parse the JSON file."
        self.assertRaisesRegexp(
            ValueError,
            regex,
            policy.read_policy_from_file,
            *args
        )

    def test_read_policy_from_file_bad_object_type(self):
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": {"INVALID": {"LOCATE": "ALLOW_ALL"}}}'
            )

        args = (policy_file.name, )
        regex = "'INVALID' is not a valid ObjectType value."
        self.assertRaisesRegexp(
            ValueError,
            regex,
            policy.read_policy_from_file,
            *args
        )

    def test_read_policy_from_file_bad_operation(self):
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": {"CERTIFICATE": {"INVALID": "ALLOW_ALL"}}}'
            )

        args = (policy_file.name, )
        regex = "'INVALID' is not a valid Operation value."
        self.assertRaisesRegexp(
            ValueError,
            regex,
            policy.read_policy_from_file,
            *args
        )

    def test_read_policy_from_file_bad_permission(self):
        policy_file = tempfile.NamedTemporaryFile(
            dir=self.temp_dir,
            delete=False
        )
        with open(policy_file.name, 'w') as f:
            f.write(
                '{"test": {"CERTIFICATE": {"LOCATE": "INVALID"}}}'
            )

        args = (policy_file.name, )
        regex = "'INVALID' is not a valid Policy value."
        self.assertRaisesRegexp(
            ValueError,
            regex,
            policy.read_policy_from_file,
            *args
        )
