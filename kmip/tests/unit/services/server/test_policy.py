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
from kmip.core.messages import contents
from kmip.services.server import policy


class TestAttributePolicy(testtools.TestCase):
    """
    A test engine for AttributePolicy.
    """

    def setUp(self):
        super(TestAttributePolicy, self).setUp()

    def tearDown(self):
        super(TestAttributePolicy, self).tearDown()

    def test_init(self):
        """
        Test that an AttributePolicy can be built without any errors.
        """
        policy.AttributePolicy(contents.ProtocolVersion.create(1, 0))

    def test_is_attribute_supported(self):
        """
        Test that is_attribute_supported returns the expected results in all
        cases.
        """
        rules = policy.AttributePolicy(contents.ProtocolVersion.create(1, 0))
        attribute_a = 'Unique Identifier'
        attribute_b = 'Certificate Length'
        attribute_c = 'invalid'

        result = rules.is_attribute_supported(attribute_a)
        self.assertTrue(result)

        result = rules.is_attribute_supported(attribute_b)
        self.assertFalse(result)

        result = rules.is_attribute_supported(attribute_c)
        self.assertFalse(result)

    def test_is_attribute_deprecated(self):
        """
        Test that is_attribute_deprecated returns the expected results in all
        cases.
        """
        rules = policy.AttributePolicy(contents.ProtocolVersion.create(1, 0))
        attribute_a = 'Name'
        attribute_b = 'Certificate Subject'

        result = rules.is_attribute_deprecated(attribute_a)
        self.assertFalse(result)

        result = rules.is_attribute_deprecated(attribute_b)
        self.assertFalse(result)

        rules = policy.AttributePolicy(contents.ProtocolVersion.create(1, 1))

        result = rules.is_attribute_deprecated(attribute_b)
        self.assertTrue(result)

    def test_is_attribute_applicable_to_object_type(self):
        """
        Test that is_attribute_applicable_to_object_type returns the
        expected results in all cases.
        """
        rules = policy.AttributePolicy(contents.ProtocolVersion.create(1, 0))
        attribute = 'Cryptographic Algorithm'
        object_type_a = enums.ObjectType.SYMMETRIC_KEY
        object_type_b = enums.ObjectType.OPAQUE_DATA

        result = rules.is_attribute_applicable_to_object_type(
            attribute,
            object_type_a
        )
        self.assertTrue(result)

        result = rules.is_attribute_applicable_to_object_type(
            attribute,
            object_type_b
        )
        self.assertFalse(result)

    def test_is_attribute_multivalued(self):
        """
        Test that is_attribute_multivalued returns the expected results in
        all cases.
        """
        rules = policy.AttributePolicy(contents.ProtocolVersion.create(1, 0))
        attribute_a = 'Object Type'
        attribute_b = 'Link'

        result = rules.is_attribute_multivalued(attribute_a)
        self.assertFalse(result)

        result = rules.is_attribute_multivalued(attribute_b)
        self.assertTrue(result)
