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

from kmip.core.attributes import ApplicationData
from kmip.core.attributes import ApplicationNamespace
from kmip.core.attributes import ApplicationSpecificInformation

from kmip.core.utils import BytearrayStream


class TestApplicationSpecificInformation(TestCase):
    """
    A test suite for the ApplicationSpecificInformation class.
    """

    def setUp(self):
        super(TestApplicationSpecificInformation, self).setUp()

        self.encoding_default = BytearrayStream((
            b'\x42\x00\x04\x01\x00\x00\x00\x10\x42\x00\x03\x07\x00\x00\x00\x00'
            b'\x42\x00\x02\x07\x00\x00\x00\x00'))
        self.encoding = BytearrayStream((
            b'\x42\x00\x04\x01\x00\x00\x00\x28\x42\x00\x03\x07\x00\x00\x00\x03'
            b'\x73\x73\x6C\x00\x00\x00\x00\x00\x42\x00\x02\x07\x00\x00\x00\x0F'
            b'\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D'
            b'\x00'))

    def tearDown(self):
        super(TestApplicationSpecificInformation, self).tearDown()

    def _test_init(self, application_namespace, application_data):
        application_specific_information = ApplicationSpecificInformation(
            application_namespace=application_namespace,
            application_data=application_data)

        if application_namespace is None:
            self.assertEqual(
                ApplicationNamespace(),
                application_specific_information.application_namespace)
        else:
            self.assertEqual(
                application_namespace,
                application_specific_information.application_namespace)

        if application_data is None:
            self.assertEqual(
                ApplicationData(),
                application_specific_information.application_data)
        else:
            self.assertEqual(
                application_data,
                application_specific_information.application_data)

    def test_init_with_none(self):
        """
        Test that an ApplicationSpecificInformation object can be constructed
        with no specified values.
        """
        self._test_init(None, None)

    def test_init_with_args(self):
        """
        Test that an ApplicationSpecificInformation object can be constructed
        with valid values.
        """
        application_namespace = ApplicationNamespace("namespace")
        application_data = ApplicationData("data")
        self._test_init(application_namespace, application_data)

    def test_validate_on_invalid_application_namespace(self):
        """
        Test that a TypeError exception is raised when an invalid
        ApplicationNamespace value is used to construct an
        ApplicationSpecificInformation object.
        """
        application_namespace = "invalid"
        application_data = ApplicationData()
        args = [application_namespace, application_data]

        self.assertRaisesRegexp(
            TypeError, "invalid application namespace",
            ApplicationSpecificInformation, *args)

    def test_validate_on_invalid_application_data(self):
        """
        Test that a TypeError exception is raised when an invalid
        ApplicationData value is used to construct an
        ApplicationSpecificInformation object.
        """
        application_namespace = ApplicationNamespace()
        application_data = "invalid"
        args = [application_namespace, application_data]

        self.assertRaisesRegexp(
            TypeError, "invalid application data",
            ApplicationSpecificInformation, *args)

    def _test_read(self, stream, application_namespace, application_data):
        application_specific_information = ApplicationSpecificInformation()
        application_specific_information.read(stream)

        if application_namespace is None:
            application_namespace = ApplicationNamespace()
        if application_data is None:
            application_data = ApplicationData()

        msg = "application namespace encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            application_namespace,
            application_specific_information.application_namespace)
        self.assertEqual(
            application_namespace,
            application_specific_information.application_namespace, msg)

        msg = "application data encoding mismatch"
        msg += "; expected {0}, observed {1}".format(
            application_data,
            application_specific_information.application_data)
        self.assertEqual(
            application_data,
            application_specific_information.application_data, msg)

    def test_read_with_none(self):
        """
        Test that an ApplicationSpecificInformation object with no data can be
        read from a data stream.
        """
        self._test_read(self.encoding_default, None, None)

    def test_read_with_args(self):
        """
        Test that an ApplicationSpecificInformation object with data can be
        read from a data stream.
        """
        application_namespace = ApplicationNamespace("ssl")
        application_data = ApplicationData("www.example.com")
        self._test_read(self.encoding, application_namespace, application_data)

    def _test_write(self, stream_expected, application_namespace,
                    application_data):
        stream_observed = BytearrayStream()
        application_specific_information = ApplicationSpecificInformation(
            application_namespace=application_namespace,
            application_data=application_data)
        application_specific_information.write(stream_observed)

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
        Test that an ApplicationSpecificInformation object with no data can be
        written to a data stream.
        """
        self._test_write(self.encoding_default, None, None)

    def test_write_with_args(self):
        """
        Test that an ApplicationSpecificInformation object with data can be
        written to a data stream.
        """
        application_namespace = ApplicationNamespace("ssl")
        application_data = ApplicationData("www.example.com")
        self._test_write(self.encoding, application_namespace,
                         application_data)

    def test_repr(self):
        """
        Test that an ApplicationSpecificInformation object can be represented
        using repr correctly.
        """
        application_specific_info = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace("ssl"),
            application_data=ApplicationData("www.example.com")
        )
        s = repr(application_specific_info)

        self.assertEqual(
            "ApplicationSpecificInformation("
            "application_namespace=ApplicationNamespace(value='ssl'), "
            "application_data=ApplicationData(value='www.example.com'))",
            s
        )

    def test_str(self):
        """
        Test that an ApplicationSpecificInformation object can be turned into
        a string correctly.
        """
        application_specific_info = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace("ssl"),
            application_data=ApplicationData("www.example.com")
        )
        s = str(application_specific_info)

        self.assertEqual(
            str({'application_namespace': 'ssl',
                 'application_data': 'www.example.com'}
                ),
            s
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        ApplicationSpecificInformation objects with the same data.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data')
        )
        b = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data')
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_namespace(self):
        """
        Test that the equality operator returns False when comparing two
        ApplicationSpecificInformation objects with different data.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace_1'),
            application_data=ApplicationData('test_data')
        )
        b = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace_2'),
            application_data=ApplicationData('test_data')
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_data(self):
        """
        Test that the equality operator returns False when comparing two
        ApplicationSpecificInformation objects with different data.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data_1')
        )
        b = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data_2')
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        ApplicationSpecificInformation object to a
        non-ApplicationSpecificInformation object.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data')
        )
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two ApplicationSpecificInformation objects with the same internal
        data.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data')
        )
        b = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data')
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_namespace(self):
        """
        Test that the inequality operator returns True when comparing two
        ApplicationSpecificInformation objects with different data.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace_1'),
            application_data=ApplicationData('test_data')
        )
        b = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace_2'),
            application_data=ApplicationData('test_data')
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_data(self):
        """
        Test that the inequality operator returns True when comparing two
        ApplicationSpecificInformation objects with different data.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data_1')
        )
        b = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data_2')
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        ApplicationSpecificInformation object to a
        non-ApplicationSpecificInformation object.
        """
        a = ApplicationSpecificInformation(
            application_namespace=ApplicationNamespace('test_namespace'),
            application_data=ApplicationData('test_data')
        )
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def _test_create(self, application_namespace, application_data):
        application_specific_info = ApplicationSpecificInformation.create(
            application_namespace, application_data)

        self.assertIsInstance(
            application_specific_info, ApplicationSpecificInformation)

        expected = ApplicationNamespace(application_namespace)
        observed = application_specific_info.application_namespace

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        expected = ApplicationData(application_data)
        observed = application_specific_info.application_data

        msg = "expected {0}, observed {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

    def test_create_with_none(self):
        """
        Test that an ApplicationSpecificInformation object with no data can be
        created using the create class method.
        """
        self._test_create(None, None)

    def test_create_with_args(self):
        """
        Test that an ApplicationSpecificInformation object with data can be
        created using the create class method.
        """
        application_namespace = "ssl"
        application_data = "www.example.com"
        self._test_create(application_namespace, application_data)
