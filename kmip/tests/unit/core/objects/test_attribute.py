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

from kmip.core import attributes
from kmip.core import objects

class TestAttribute(testtools.TestCase):
    """
    Test suite for the Attribute object.
    """

    def setUp(self):
        super(TestAttribute, self).setUp()

    def tearDown(self):
        super(TestAttribute, self).tearDown()

    def test_init(self):
        """
        Test that an Attribute object can be created.
        """
        objects.Attribute()

    def test_init_with_args(self):
        self.skipTest('')

    def test_read(self):
        self.skipTest('')

    def test_write(self):
        self.skipTest('')

    def test_repr(self):
        """
        Test that repr can be applied to an Attribute object.
        """
        attribute = objects.Attribute(
            attribute_name=objects.Attribute.AttributeName('test-name'),
            attribute_index=objects.Attribute.AttributeIndex(0),
            attribute_value=attributes.CustomAttribute('test-value')
        )

        self.assertEqual(
            "Attribute("
            "attribute_name=AttributeName(value='test-name'), "
            "attribute_index=AttributeIndex(value=0), "
            "attribute_value=CustomAttribute(value='test-value'))",
            repr(attribute)
        )

    def test_str(self):
        """
        Test that str can be applied to an Attribute object.
        """
        attribute = objects.Attribute(
            attribute_name=objects.Attribute.AttributeName('test-name'),
            attribute_index=objects.Attribute.AttributeIndex(0),
            attribute_value=attributes.CustomAttribute('test-value')
        )

        self.assertEqual(
            str({
                'attribute_name': 'test-name',
                'attribute_index': '0',
                'attribute_value': 'test-value'
            }),
            str(attribute)
        )

    def test_equal_on_equal(self):
        self.skipTest('')

    def test_equal_on_not_equal_name(self):
        self.skipTest('')

    def test_equal_on_not_equal_index(self):
        self.skipTest('')

    def test_equal_on_not_equal_value(self):
        self.skipTest('')

    def test_equal_on_type_mismatch(self):
        self.skipTest('')

    def test_not_equal_on_equal(self):
        self.skipTest('')

    def test_not_equal_on_not_equal_name(self):
        self.skipTest('')

    def test_not_equal_on_not_equal_index(self):
        self.skipTest('')

    def test_not_equal_on_not_equal_value(self):
        self.skipTest('')

    def test_not_equal_on_type_mismatch(self):
        self.skipTest('')
