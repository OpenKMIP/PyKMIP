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

import testtools

from kmip.core import utils


class TestDateTime(testtools.TestCase):

    def setUp(self):
        super(TestDateTime, self).setUp()
        self.stream = utils.BytearrayStream()

    def tearDown(self):
        super(TestDateTime, self).tearDown()

    def test_init(self):
        self.skip('')

    def test_init_unset(self):
        self.skip('')

    def test_validate_on_valid(self):
        self.skip('')

    def test_validate_on_valid_unset(self):
        self.skip('')

    def test_validate_on_invalid_type(self):
        self.skip('')

    def test_read(self):
        self.skip('')

    def test_write(self):
        self.skip('')
