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

import testtools

from kmip.core import enums

from kmip.core.factories import attributes

class TestAttributeFactory(testtools.TestCase):
    """
    Test suite for Attribute Factory
    """

    def setUp(self):
        super(TestAttributeFactory, self).setUp()
        self.attribute_factory = attributes.AttributeFactory()

    def tearDown(self):
        super(TestAttributeFactory, self).tearDown()

    def test_name_eq(self):
        """
        Test that two identical name attributes match
        """
        attr_type = enums.AttributeType.NAME
        attr_name = "foo"
        attr_a = self.attribute_factory.create_attribute(attr_type, attr_name)
        attr_b = self.attribute_factory.create_attribute(attr_type, attr_name)
        self.assertTrue(attr_a == attr_b)
        self.assertFalse(attr_a != attr_b)
