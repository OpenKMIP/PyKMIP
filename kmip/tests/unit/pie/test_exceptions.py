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

from kmip.core.enums import ResultStatus
from kmip.core.enums import ResultReason

from kmip.pie.exceptions import ClientConnectionFailure
from kmip.pie.exceptions import ClientConnectionNotOpen
from kmip.pie.exceptions import KmipOperationFailure


class TestClientConnectionFailure(TestCase):
    """
    Test suite for ClientConnectionFailure.
    """

    def setUp(self):
        super(TestClientConnectionFailure, self).setUp()

    def tearDown(self):
        super(TestClientConnectionFailure, self).tearDown()

    def test_init(self):
        """
        Test that a ClientConnectionFailure exception can be instantiated.
        """
        exc = ClientConnectionFailure()
        self.assertIsInstance(exc, Exception)

    def test_message(self):
        """
        Test that a ClientConnectionFailure exception message can be set
        properly.
        """
        exc = ClientConnectionFailure("test message")
        self.assertEqual("test message", str(exc))


class TestClientConnectionNotOpen(TestCase):
    """
    Test suite for ClientConnectionNotOpen.
    """

    def setUp(self):
        super(TestClientConnectionNotOpen, self).setUp()

    def tearDown(self):
        super(TestClientConnectionNotOpen, self).tearDown()

    def test_init(self):
        """
        Test that a ClientConnectionNotOpen exception can be instantiated.
        """
        exc = ClientConnectionNotOpen()
        self.assertIsInstance(exc, Exception)
        self.assertEqual("client connection not open", str(exc))


class TestKmipOperationFailure(TestCase):
    """
    Test suite for KmipOperationFailure.
    """

    def setUp(self):
        super(TestKmipOperationFailure, self).setUp()

    def tearDown(self):
        super(TestKmipOperationFailure, self).tearDown()

    def test_init(self):
        """
        Test that a KmipOperationFailure exception can be instantiated.
        """
        exc = KmipOperationFailure(
            ResultStatus.OPERATION_FAILED,
            ResultReason.GENERAL_FAILURE,
            "Test error message.")
        self.assertIsInstance(exc, Exception)

    def test_message(self):
        """
        Test that a KmipOperationFailure exception message and attributes can
        be set properly.
        """
        status = ResultStatus.OPERATION_FAILED
        reason = ResultReason.GENERAL_FAILURE
        exc = KmipOperationFailure(status, reason, "Test error message.")

        msg = "{0}: {1} - {2}".format(
            status.name, reason.name, "Test error message.")

        self.assertEqual(msg, str(exc))
        self.assertEqual(status, exc.status)
        self.assertEqual(reason, exc.reason)
        self.assertEqual("Test error message.", exc.message)
