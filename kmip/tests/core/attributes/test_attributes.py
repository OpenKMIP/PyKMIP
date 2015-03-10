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

from kmip.core.attributes import ApplicationData
from kmip.core.attributes import ApplicationNamespace
from kmip.core.attributes import DigestValue
from kmip.core.attributes import HashingAlgorithm
from kmip.core.attributes import OperationPolicyName

from kmip.core.enums import HashingAlgorithm as HashingAlgorithmEnum

from kmip.core.utils import BytearrayStream


class TestNameValue(TestCase):

    def setUp(self):
        super(TestNameValue, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestNameValue, self).tearDown()

    def test_write_no_padding(self):
        self.skip('Not implemented')

    def test_write_with_padding(self):
        self.skip('Not implemented')

    def test_read_no_padding(self):
        self.skip('Not implemented')

    def test_read_with_padding(self):
        self.skip('Not implemented')


class TestName(TestCase):

    def setUp(self):
        super(TestName, self).setUp()
        self.stream = BytearrayStream()

    def tearDown(self):
        super(TestName, self).tearDown()

    def test_minimum_write(self):
        self.skip('Not implemented')

    def test_maximum_write(self):
        self.skip('Not implemented')

    def test_minimum_read(self):
        self.skip('Not implemented')

    def test_maximum_read(self):
        self.skip('Not implemented')


class TestOperationPolicyName(TestCase):

    def setUp(self):
        super(TestOperationPolicyName, self).setUp()

    def tearDown(self):
        super(TestOperationPolicyName, self).tearDown()

    def _test_operation_policy_name(self, value):
        opn = OperationPolicyName(value)

        if value is None:
            value = ''

        msg = "expected {0}, received {1}".format(value, opn.value)
        self.assertEqual(value, opn.value, msg)

    def test_operation_policy_name(self):
        self._test_operation_policy_name('test')

    def test_operation_policy_name_on_none(self):
        self._test_operation_policy_name(None)


class TestHashingAlgorithm(TestCase):
    """
    A test suite for the HashingAlgorithm class.

    Since HashingAlgorithm is a simple wrapper for the Enumeration primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestHashingAlgorithm, self).setUp()

    def tearDown(self):
        super(TestHashingAlgorithm, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, HashingAlgorithmEnum)) or (value is None):
            hashing_algorithm = HashingAlgorithm(value)

            msg = "expected {0}, observed {1}".format(
                value, hashing_algorithm.enum)
            self.assertEqual(value, hashing_algorithm.enum, msg)
        else:
            self.assertRaises(TypeError, HashingAlgorithm, value)

    def test_init_with_none(self):
        """
        Test that a HashingAlgorithm object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a HashingAlgorithm object can be constructed with a valid
        HashingAlgorithm enumeration value.
        """
        self._test_init(HashingAlgorithmEnum.MD5)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non HashingAlgorithm
        enumeration value is used to construct a HashingAlgorithm object.
        """
        self._test_init("invalid")


class TestDigestValue(TestCase):
    """
    A test suite for the DigestValue class.

    Since DigestValue is a simple wrapper for the ByteString primitive, only
    a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestDigestValue, self).setUp()

    def tearDown(self):
        super(TestDigestValue, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, bytes)) or (value is None):
            digest_value = DigestValue(value)

            if value is None:
                value = bytes()

            msg = "expected {0}, observed {1}".format(
                value, digest_value.value)
            self.assertEqual(value, digest_value.value, msg)
        else:
            self.assertRaises(TypeError, DigestValue, value)

    def test_init_with_none(self):
        """
        Test that a DigestValue object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a DigestValue object can be constructed with valid byte data.
        """
        self._test_init(b'\x00\x01\x02\x03')


class TestApplicationNamespace(TestCase):
    """
    A test suite for the ApplicationNamespace class.

    Since ApplicationNamespace is a simple wrapper for the TextString
    primitive, only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestApplicationNamespace, self).setUp()

    def tearDown(self):
        super(TestApplicationNamespace, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, str)) or (value is None):
            application_namespace = ApplicationNamespace(value)

            if value is None:
                value = ''

            msg = "expected {0}, observed {1}".format(
                value, application_namespace.value)
            self.assertEqual(value, application_namespace.value, msg)
        else:
            self.assertRaises(TypeError, ApplicationNamespace, value)

    def test_init_with_none(self):
        """
        Test that an ApplicationNamespace object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ApplicationNamespace object can be constructed with a
        valid, string-type value.
        """
        self._test_init("valid")

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ApplicationNamespace object.
        """
        self._test_init(0)


class TestApplicationData(TestCase):
    """
    A test suite for the ApplicationData class.

    Since ApplicationData is a simple wrapper for the TextString primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestApplicationData, self).setUp()

    def tearDown(self):
        super(TestApplicationData, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, str)) or (value is None):
            application_data = ApplicationData(value)

            if value is None:
                value = ''

            msg = "expected {0}, observed {1}".format(
                value, application_data.value)
            self.assertEqual(value, application_data.value, msg)
        else:
            self.assertRaises(TypeError, ApplicationData, value)

    def test_init_with_none(self):
        """
        Test that an ApplicationData object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that an ApplicationData object can be constructed with a
        valid, string-type value.
        """
        self._test_init("valid")

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct an ApplicationData object.
        """
        self._test_init(0)
