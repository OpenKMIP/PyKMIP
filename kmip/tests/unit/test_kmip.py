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

from testtools import TestCase

class TestKMIP(TestCase):
    """
    A test suite for the overall `kmip` module.
    """

    def setUp(self):
        super(TestKMIP, self).setUp()

    def tearDown(self):
        super(TestKMIP, self).tearDown()

    def test_version(self):
        """
        Verify that the kmip module has a __version__ attribute and that it's
        value is correct.
        """
        kmip = __import__('kmip')
        self.assertTrue(hasattr(kmip, '__version__'))

        version = __import__('kmip.version')
        self.assertTrue(hasattr(version, '__version__'))

        observed = getattr(kmip, '__version__')
        expected = getattr(version, '__version__')
        self.assertEqual(expected, observed)
