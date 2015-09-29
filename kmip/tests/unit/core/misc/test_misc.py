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

from six import binary_type
from six import string_types

from testtools import TestCase

from kmip.core.enums import KeyFormatType as KeyFormatTypeEnum
from kmip.core.enums import QueryFunction as QueryFunctionEnum

from kmip.core.misc import CertificateValue
from kmip.core.misc import KeyFormatType
from kmip.core.misc import QueryFunction
from kmip.core.misc import VendorIdentification


# TODO (peter-hamilton) Replace with generic ByteString subclass test suite.
class TestCertificateValue(TestCase):
    """
    A test suite for the CertificateValue class.

    Since CertificateValue is a simple wrapper for the ByteString primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestCertificateValue, self).setUp()

    def tearDown(self):
        super(TestCertificateValue, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, binary_type)) or (value is None):
            certificate_value = CertificateValue(value)

            if value is None:
                value = b''

            msg = "expected {0}, observed {1}".format(
                value, certificate_value.value)
            self.assertEqual(value, certificate_value.value, msg)
        else:
            self.assertRaises(TypeError, CertificateValue, value)

    def test_init_with_none(self):
        """
        Test that a CertificateValue object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a CertificateValue object can be constructed with a valid,
        byte-string value.
        """
        self._test_init(b'\x00\x01\x02')


class TestQueryFunction(TestCase):
    """
    A test suite for the QueryFunction class.

    Since QueryFunction is a simple wrapper for the Enumeration primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestQueryFunction, self).setUp()

    def tearDown(self):
        super(TestQueryFunction, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, QueryFunctionEnum)) or (value is None):
            query_function = QueryFunction(value)

            msg = "expected {0}, observed {1}".format(
                value, query_function.value)
            self.assertEqual(value, query_function.value, msg)
        else:
            self.assertRaises(TypeError, QueryFunction, value)

    def test_init_with_none(self):
        """
        Test that a QueryFunction object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a QueryFunction object can be constructed with a valid
        QueryFunction enumeration value.
        """
        self._test_init(QueryFunctionEnum.QUERY_OBJECTS)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non QueryFunction
        enumeration value is used to construct a QueryFunction object.
        """
        self._test_init("invalid")


class TestVendorIdentification(TestCase):
    """
    A test suite for the VendorIdentification class.

    Since VendorIdentification is a simple wrapper for the TextString
    primitive, only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestVendorIdentification, self).setUp()

    def tearDown(self):
        super(TestVendorIdentification, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, string_types)) or (value is None):
            vendor_identification = VendorIdentification(value)

            if value is None:
                value = ''

            msg = "expected {0}, observed {1}".format(
                value, vendor_identification.value)
            self.assertEqual(value, vendor_identification.value, msg)
        else:
            self.assertRaises(TypeError, VendorIdentification, value)

    def test_init_with_none(self):
        """
        Test that a VendorIdentification object can be constructed with no
        specified value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a VendorIdentification object can be constructed with a
        valid, string-type value.
        """
        self._test_init("valid")

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non-string value is
        used to construct a VendorIdentification object.
        """
        self._test_init(0)


class TestKeyFormatType(TestCase):
    """
    A test suite for the KeyFormatType class.

    Since KeyFormatType is a simple wrapper for the Enumeration primitive,
    only a few tests pertaining to construction are needed.
    """

    def setUp(self):
        super(TestKeyFormatType, self).setUp()

    def tearDown(self):
        super(TestKeyFormatType, self).tearDown()

    def _test_init(self, value):
        if (isinstance(value, KeyFormatTypeEnum)) or (value is None):
            key_format_type = KeyFormatType(value)

            msg = "expected {0}, observed {1}".format(
                value, key_format_type.value)
            self.assertEqual(value, key_format_type.value, msg)
        else:
            self.assertRaises(TypeError, KeyFormatType, value)

    def test_init_with_none(self):
        """
        Test that a KeyFormatType object can be constructed with no specified
        value.
        """
        self._test_init(None)

    def test_init_with_valid(self):
        """
        Test that a KeyFormatType object can be constructed with a valid
        KeyFormatType enumeration value.
        """
        self._test_init(KeyFormatTypeEnum.RAW)

    def test_init_with_invalid(self):
        """
        Test that a TypeError exception is raised when a non KeyFormatType
        enumeration value is used to construct a KeyFormatType object.
        """
        self._test_init("invalid")
