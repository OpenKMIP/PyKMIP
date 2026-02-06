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

from kmip.pie.objects import CryptographicObject

class DummyCryptographicObject(CryptographicObject):
    """
    A dummy CryptographicObject subclass for testing purposes.
    """

    def __init__(self):
        """
        Create a DummyCryptographicObject
        """
        super(DummyCryptographicObject, self).__init__()

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

class TestCryptographicObject(TestCase):
    """
    Test suite for CryptographicObject.

    Since CryptographicObject is an ABC abstract class, all tests are run
    against a dummy subclass defined above, DummyCryptographicObject.
    """

    def setUp(self):
        super(TestCryptographicObject, self).setUp()

    def tearDown(self):
        super(TestCryptographicObject, self).tearDown()

    def test_init(self):
        """
        Test that a complete subclass of CryptographicObject can be
        instantiated.
        """
        DummyCryptographicObject()

    def test_repr(self):
        """
        Test that repr can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        repr(dummy)

    def test_str(self):
        """
        Test that str can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        str(dummy)

    def test_eq(self):
        """
        Test that equality can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        self.assertTrue(dummy == dummy)

    def test_ne(self):
        """
        Test that inequality can be applied to a CryptographicObject.
        """
        dummy = DummyCryptographicObject()
        self.assertFalse(dummy != dummy)
