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

from kmip.core import primitives
from kmip.core import utils

class TestDateTime(testtools.TestCase):
    """
    Test suite for the DateTime primitive.

    Since DateTime is a subclass of LongInteger, the bulk of the functionality
    tests are omitted due to redundancy with the LongInteger test suite.
    """

    def setUp(self):
        super(TestDateTime, self).setUp()

        self.value = 1335514341
        self.encoding = (
            b'\x42\x00\x00\x09\x00\x00\x00\x08\x00\x00\x00\x00\x4F\x9A\x54'
            b'\xE5')

    def tearDown(self):
        super(TestDateTime, self).tearDown()

    def test_init(self):
        """
        Test that a DateTime can be instantiated.
        """
        date_time = primitives.DateTime(1)
        self.assertEqual(1, date_time.value)

    def test_init_unset(self):
        """
        Test that a DateTime can be instantiated with no input.
        """
        date_time = primitives.DateTime()
        self.assertNotEqual(date_time.value, None)

    def test_read(self):
        """
        Test that a DateTime can be read from a byte stream.
        """
        stream = utils.BytearrayStream(self.encoding)
        date_time = primitives.DateTime()
        date_time.read(stream)
        self.assertEqual(self.value, date_time.value)

    def test_write(self):
        """
        Test that a DateTime can be written to a byte stream.
        """
        stream = utils.BytearrayStream()
        date_time = primitives.DateTime(self.value)
        date_time.write(stream)

        result = stream.read()
        self.assertEqual(len(self.encoding), len(result))
        self.assertEqual(self.encoding, result)

    def test_repr(self):
        """
        Test that the representation of a DateTime is formatted properly.
        """
        date_time = primitives.DateTime(1439299135)
        value = "value={0}".format(date_time.value)
        tag = "tag={0}".format(date_time.tag)
        r = "DateTime({0}, {1})".format(value, tag)

        self.assertEqual(r, repr(date_time))

    def test_str(self):
        """
        Test that the string representation of a DateTime is formatted
        properly.
        """
        expected = 'Tue Aug 11 13:18:55 2015'
        date_time = primitives.DateTime(1439299135)

        self.assertEqual(expected, str(date_time))
