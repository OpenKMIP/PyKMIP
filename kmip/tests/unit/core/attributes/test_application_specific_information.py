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

from kmip.core import attributes
from kmip.core import exceptions
from kmip.core import utils

class TestApplicationSpecificInformation(testtools.TestCase):
    """
    A test suite for the ApplicationSpecificInformation class.
    """

    def setUp(self):
        super(TestApplicationSpecificInformation, self).setUp()

        # This encoding was taken from test case 3.1.2 from the KMIP 1.1 test
        # document.
        #
        # This encoding matches the following set of values:
        # Application Specific Information
        #     Application Namespace - ssl
        #     Application Data - www.example.com
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x04\x01\x00\x00\x00\x28'
            b'\x42\x00\x03\x07\x00\x00\x00\x03\x73\x73\x6C\x00\x00\x00\x00\x00'
            b'\x42\x00\x02\x07\x00\x00\x00\x0F'
            b'\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x00'
        )

        # This encoding was adapted from test case 3.1.2 from the KMIP 1.1 test
        # document.
        #
        # This encoding matches the following set of values:
        # Application Specific Information
        #     Application Data - www.example.com
        self.no_application_namespace_encoding = utils.BytearrayStream(
            b'\x42\x00\x04\x01\x00\x00\x00\x18'
            b'\x42\x00\x02\x07\x00\x00\x00\x0F'
            b'\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D\x00'
        )

        # This encoding was adapted from test case 3.1.2 from the KMIP 1.1 test
        # document.
        #
        # This encoding matches the following set of values:
        # Application Specific Information
        #     Application Namespace - ssl
        self.no_application_data_encoding = utils.BytearrayStream(
            b'\x42\x00\x04\x01\x00\x00\x00\x10'
            b'\x42\x00\x03\x07\x00\x00\x00\x03\x73\x73\x6C\x00\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestApplicationSpecificInformation, self).tearDown()

    def test_init(self):
        """
        Test that an ApplicationSpecificInformation object can be constructed.
        """
        app_specific_info = attributes.ApplicationSpecificInformation()

        self.assertIsNone(app_specific_info.application_namespace)
        self.assertIsNone(app_specific_info.application_data)

        app_specific_info = attributes.ApplicationSpecificInformation(
            application_namespace="namespace",
            application_data="data"
        )

        self.assertEqual("namespace", app_specific_info.application_namespace)
        self.assertEqual("data", app_specific_info.application_data)

    def test_invalid_application_namespace(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the application namespace of an ApplicationSpecificInformation object.
        """
        kwargs = {"application_namespace": []}
        self.assertRaisesRegex(
            TypeError,
            "The application namespace must be a string.",
            attributes.ApplicationSpecificInformation,
            **kwargs
        )

        args = (
            attributes.ApplicationSpecificInformation(),
            "application_namespace",
            []
        )
        self.assertRaisesRegex(
            TypeError,
            "The application namespace must be a string.",
            setattr,
            *args
        )

    def test_invalid_application_data(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the application data of an ApplicationSpecificInformation object.
        """
        kwargs = {"application_data": []}
        self.assertRaisesRegex(
            TypeError,
            "The application data must be a string.",
            attributes.ApplicationSpecificInformation,
            **kwargs
        )

        args = (
            attributes.ApplicationSpecificInformation(),
            "application_data",
            []
        )
        self.assertRaisesRegex(
            TypeError,
            "The application data must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an ApplicationSpecificInformation object can be read from a
        buffer.
        """
        app_specific_info = attributes.ApplicationSpecificInformation()

        self.assertIsNone(app_specific_info.application_namespace)
        self.assertIsNone(app_specific_info.application_data)

        app_specific_info.read(self.full_encoding)

        self.assertEqual("ssl", app_specific_info.application_namespace)
        self.assertEqual("www.example.com", app_specific_info.application_data)

    def test_read_missing_application_namespace(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding of
        an ApplicationSpecificInformation object with the application namespace
        is missing from the encoding.
        """
        app_specific_info = attributes.ApplicationSpecificInformation()

        self.assertIsNone(app_specific_info.application_namespace)

        args = (self.no_application_namespace_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ApplicationSpecificInformation encoding is missing the "
            "ApplicationNamespace field.",
            app_specific_info.read,
            *args
        )

    def test_read_missing_application_data(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding of
        an ApplicationSpecificInformation object with the application data is
        missing from the encoding.
        """
        app_specific_info = attributes.ApplicationSpecificInformation()

        self.assertIsNone(app_specific_info.application_data)

        args = (self.no_application_data_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The ApplicationSpecificInformation encoding is missing the "
            "ApplicationData field.",
            app_specific_info.read,
            *args
        )

    def test_write(self):
        """
        Test that an ApplicationSpecificInformation object can be written to a
        buffer.
        """
        app_specific_info = attributes.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        buff = utils.BytearrayStream()
        app_specific_info.write(buff)

        self.assertEqual(len(self.full_encoding), len(buff))
        self.assertEqual(str(self.full_encoding), str(buff))

    def test_write_missing_application_namespace(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ApplicationSpecificInformation object when the object is missing the
        application namespace field.
        """
        app_specific_info = attributes.ApplicationSpecificInformation(
            application_data="www.example.com"
        )

        buff = utils.BytearrayStream()
        args = (buff, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ApplicationSpecificInformation object is missing the "
            "ApplicationNamespace field.",
            app_specific_info.write,
            *args
        )

    def test_write_missing_application_data(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        ApplicationSpecificInformation object when the object is missing the
        application data field.
        """
        app_specific_info = attributes.ApplicationSpecificInformation(
            application_namespace="ssl"
        )

        buff = utils.BytearrayStream()
        args = (buff, )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The ApplicationSpecificInformation object is missing the "
            "ApplicationData field.",
            app_specific_info.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to an ApplicationSpecificInformation
        object.
        """
        app_specific_info = attributes.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        args = [
            "application_namespace='ssl'",
            "application_data='www.example.com'"
        ]
        self.assertEqual(
            "ApplicationSpecificInformation({})".format(", ".join(args)),
            repr(app_specific_info)
        )

    def test_str(self):
        """
        Test that str can be applied to an ApplicationSpecificInformation
        object.
        """
        app_specific_info = attributes.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        args = [
            ("application_namespace", "ssl"),
            ("application_data", "www.example.com")
        ]
        value = "{}".format(
            ", ".join(['"{}": "{}"'.format(arg[0], arg[1]) for arg in args])
        )
        self.assertEqual(
            "{" + value + "}",
            str(app_specific_info)
        )

    def test_comparison(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two ApplicationSpecificInformation objects with the same
        data.
        """
        a = attributes.ApplicationSpecificInformation()
        b = attributes.ApplicationSpecificInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = attributes.ApplicationSpecificInformation(
            application_namespace="test_namespace",
            application_data="test_data"
        )
        b = attributes.ApplicationSpecificInformation(
            application_namespace="test_namespace",
            application_data="test_data"
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_application_namespaces(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ApplicationSpecificInformation objects with different
        data.
        """
        a = attributes.ApplicationSpecificInformation(
            application_namespace="test_namespace_1"
        )
        b = attributes.ApplicationSpecificInformation(
            application_namespace="test_namespace_2"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_application_data(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ApplicationSpecificInformation objects with different
        data.
        """
        a = attributes.ApplicationSpecificInformation(
            application_data="test_data_1"
        )
        b = attributes.ApplicationSpecificInformation(
            application_data="test_data_2"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing an ApplicationSpecificInformation object to a
        non-ApplicationSpecificInformation object.
        """
        a = attributes.ApplicationSpecificInformation(
            application_namespace="test_namespace",
            application_data="test_data"
        )
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
