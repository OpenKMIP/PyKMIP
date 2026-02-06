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

from kmip.pie.objects import Key

class DummyKey(Key):
    """
    A dummy Key subclass for testing purposes.
    """

    def __init__(self):
        """
        Create a DummyKey
        """
        super(DummyKey, self).__init__()

    def validate(self):
        return

    def __repr__(self):
        return ''

    def __str__(self):
        return ''

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

class TestKey(TestCase):
    """
    Test suite for Key.

    Since Key is an ABC abstract class, all tests are run against a dummy
    subclass defined above, DummyKey.
    """

    def setUp(self):
        super(TestKey, self).setUp()

    def tearDown(self):
        super(TestKey, self).tearDown()

    def test_init(self):
        """
        Test that a complete subclass of Key can be
        instantiated.
        """
        DummyKey()

    def test_repr(self):
        """
        Test that repr can be applied to a Key.
        """
        dummy = DummyKey()
        repr(dummy)

    def test_str(self):
        """
        Test that str can be applied to a Key.
        """
        dummy = DummyKey()
        str(dummy)

    def test_eq(self):
        """
        Test that equality can be applied to a Key.
        """
        dummy = DummyKey()
        self.assertTrue(dummy == dummy)

    def test_ne(self):
        """
        Test that inequality can be applied to a Key.
        """
        dummy = DummyKey()
        self.assertFalse(dummy != dummy)

    def test_key_wrapping_data_invalid(self):
        """
        Test that the right error is raised when setting the key wrapping
        data with an invalid value.
        """
        dummy = DummyKey()
        args = (dummy, 'key_wrapping_data', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Key wrapping data must be a dictionary.",
            setattr,
            *args
        )
