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

from kmip.core.misc import ServerInformation
from kmip.core.utils import BytearrayStream

class TestServerInformation(TestCase):
    """
    A test suite for the ServerInformation class.
    """

    def setUp(self):
        super(TestServerInformation, self).setUp()

        self.data = BytearrayStream(b'\x00\x01\x02\x03')

        self.encoding_a = BytearrayStream(
            b'\x42\x00\x88\x01\x00\x00\x00\x00')
        self.encoding_b = BytearrayStream(
            b'\x42\x00\x88\x01\x00\x00\x00\x04\x00\x01\x02\x03')

    def tearDown(self):
        super(TestServerInformation, self).tearDown()

    def test_init(self):
        ServerInformation()

    def _test_read(self, stream, data):
        server_information = ServerInformation()
        server_information.read(stream)

        expected = data
        observed = server_information.data

        msg = "data decoding mismatch"
        msg += "; expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_read_with_none(self):
        """
        Test that a ServerInformation object with no data can be read from a
        data stream.
        """
        self._test_read(self.encoding_a, BytearrayStream())

    def test_read_with_data(self):
        """
        Test that a ServerInformation object with data can be read from a
        data stream.
        """
        self._test_read(self.encoding_b, self.data)

    def _test_write(self, stream_expected, data):
        stream_observed = BytearrayStream()
        server_information = ServerInformation()

        if data is not None:
            server_information.data = data

        server_information.write(stream_observed)

        length_expected = len(stream_expected)
        length_observed = len(stream_observed)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, observed {1}".format(
            length_expected, length_observed)
        self.assertEqual(length_expected, length_observed, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nobserved:\n{1}".format(
            stream_expected, stream_observed)
        self.assertEqual(stream_expected, stream_observed, msg)

    def test_write_with_none(self):
        """
        Test that a ServerInformation object with no data can be written to a
        data stream.
        """
        self._test_write(self.encoding_a, None)

    def test_write_with_data(self):
        """
        Test that a ServerInformation object with data can be written to a
        data stream.
        """
        self._test_write(self.encoding_b, self.data)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ServerInformation objects with the same internal data.
        """
        a = ServerInformation()
        b = ServerInformation()

        a.data = self.data
        b.data = self.data

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_equal_and_empty(self):
        """
        Test that the equality operator returns True when comparing two
        ServerInformation objects with no internal data.
        """
        a = ServerInformation()
        b = ServerInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal(self):
        """
        Test that the equality operator returns False when comparing two
        ServerInformation objects with different sets of internal data.
        """
        a = ServerInformation()
        b = ServerInformation()

        a.data = self.data

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        ServerInformation object to a non-ServerInformation object.
        """
        a = ServerInformation()
        b = "invalid"

        self.assertFalse(a == b)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two ServerInformation objects with the same internal data.
        """
        a = ServerInformation()
        b = ServerInformation()

        a.data = self.data
        b.data = self.data

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_equal_and_empty(self):
        """
        Test that the inequality operator returns False when comparing
        two ServerInformation objects with no internal data.
        """
        a = ServerInformation()
        b = ServerInformation()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal(self):
        """
        Test that the inequality operator returns True when comparing two
        ServerInformation objects with different sets of internal data.
        """
        a = ServerInformation()
        b = ServerInformation()

        a.data = self.data

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing a
        ServerInformation object to a non-ServerInformation object.
        """
        a = ServerInformation()
        b = "invalid"

        self.assertTrue(a != b)

    def test_repr(self):
        """
        Test that the representation of a ServerInformation object is
        formatted properly and can be used by eval to create a new
        ServerInformation object.
        """
        server_information = ServerInformation()

        expected = "ServerInformation()"
        observed = repr(server_information)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = server_information
        observed = eval(observed)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def _test_str(self, data):
        server_information = ServerInformation()
        server_information.data = data
        str_repr = str(server_information)

        expected = len(str(data))
        observed = len(str_repr)

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        # TODO (peter-hamilton) This should be bytes. Fix involves
        # TODO (peter-hamilton) refining BytearrayStream implementation.
        expected = str
        observed = str_repr

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertIsInstance(observed, expected, msg)

    def test_str_with_no_data(self):
        """
        Test that the string representation of a ServerInformation object
        is formatted properly when there is no internal data.
        """
        self._test_str(BytearrayStream())

    def test_str_with_data(self):
        """
        Test that the string representation of a ServerInformation object
        is formatted properly when there is internal data.
        """
        self._test_str(self.data)
