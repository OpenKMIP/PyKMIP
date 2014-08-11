# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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

from testtools import TestCase

from kmip.core.utils import BytearrayStream


class TestNameValue(TestCase):

    def setUp(self):
        super(TestNameValue, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestNameValue, self).tearDown()

    def test_write_no_padding(self):
        pass

    def test_write_with_padding(self):
        pass

    def test_read_no_padding(self):
        pass

    def test_read_with_padding(self):
        pass


class TestName(TestCase):

    def setUp(self):
        super(TestName, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestName, self).tearDown()

    def test_minimum_write(self):
        pass

    def test_maximum_write(self):
        pass

    def test_minimum_read(self):
        pass

    def test_maximum_read(self):
        pass
