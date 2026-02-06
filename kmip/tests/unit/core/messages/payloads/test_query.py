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

from kmip.core import enums
from kmip.core import exceptions
from kmip.core import misc
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestQueryRequestPayload(testtools.TestCase):
    """
    Test suite for the QueryRequestPayload class.

    Test encodings obtained from Sections 12.1 and 12.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestQueryRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 12.1.0.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Query Functions
        #         Query Operations
        #         Query Objects
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x20'
            b'\x42\x00\x74\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x74\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Request Payload
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestQueryRequestPayload, self).tearDown()

    def test_invalid_query_functions(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the query functions of a Query request payload.
        """
        kwargs = {"query_functions": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The query functions must be a list of QueryFunction "
            "enumerations.",
            payloads.QueryRequestPayload,
            **kwargs
        )
        kwargs = {"query_functions": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The query functions must be a list of QueryFunction "
            "enumerations.",
            payloads.QueryRequestPayload,
            **kwargs
        )

        args = (
            payloads.QueryRequestPayload(),
            "query_functions",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The query functions must be a list of QueryFunction "
            "enumerations.",
            setattr,
            *args
        )
        args = (
            payloads.QueryRequestPayload(),
            "query_functions",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The query functions must be a list of QueryFunction "
            "enumerations.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a QueryRequestPayload structure can be correctly read in
        from a data stream.
        """
        payload = payloads.QueryRequestPayload()

        self.assertIsNone(payload.query_functions)

        payload.read(self.full_encoding)

        self.assertEqual(
            [
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ],
            payload.query_functions
        )

    def test_read_missing_query_functions(self):
        """
        Test that an InvalidKmipEncoding error is raised during the decoding
        of a QueryRequestPayload structure when the query functions are
        missing from the encoding.
        """
        payload = payloads.QueryRequestPayload()

        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            exceptions.InvalidKmipEncoding,
            "The Query request payload encoding is missing the query "
            "functions.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a QueryRequestPayload structure can be written to a data
        stream.
        """
        payload = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_missing_query_functions(self):
        """
        Test that an InvalidField error is raised during the encoding of an
        QueryRequestPayload structure when the structure is missing the
        query functions field.
        """
        payload = payloads.QueryRequestPayload()

        args = (utils.BytearrayStream(), )
        self.assertRaisesRegex(
            exceptions.InvalidField,
            "The Query request payload is missing the query functions field.",
            payload.write,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to a QueryRequestPayload structure.
        """
        payload = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )

        v = "query_functions=" + \
            "[QueryFunction.QUERY_OPERATIONS, QueryFunction.QUERY_OBJECTS]"

        self.assertEqual(
            "QueryRequestPayload({})".format(v),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a QueryRequestPayload structure.
        """
        payload = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )

        v = '"query_functions": ' + \
            '[QueryFunction.QUERY_OPERATIONS, QueryFunction.QUERY_OBJECTS]'

        self.assertEqual("{" + v + "}", str(payload))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        QueryRequestPayload structures with the same data.
        """
        a = payloads.QueryRequestPayload()
        b = payloads.QueryRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )
        b = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_query_functions(self):
        """
        Test that the equality operator returns False when comparing two
        QueryRequestPayload structures with different query functions fields.
        """
        a = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )
        b = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OBJECTS,
                enums.QueryFunction.QUERY_OPERATIONS
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        QueryRequestPayload structures with different types.
        """
        a = payloads.QueryRequestPayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        QueryRequestPayload structures with the same data.
        """
        a = payloads.QueryRequestPayload()
        b = payloads.QueryRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )
        b = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_query_functions(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryRequestPayload structures with different query functions fields.
        """
        a = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )
        b = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OBJECTS,
                enums.QueryFunction.QUERY_OPERATIONS
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryRequestPayload structures with different types.
        """
        a = payloads.QueryRequestPayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a Query request payload can be constructed with no
        arguments.
        """
        payload = payloads.QueryRequestPayload()
        self.assertIsNone(payload.query_functions)

    def test_init_with_args(self):
        """
        Test that a Query request payload can be constructed with valid
        values.
        """
        payload = payloads.QueryRequestPayload(
            query_functions=[
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ]
        )
        self.assertEqual(
            [
                enums.QueryFunction.QUERY_OPERATIONS,
                enums.QueryFunction.QUERY_OBJECTS
            ],
            payload.query_functions
        )

    def test_read_valid(self):
        """
        Test that a Query request payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        self.test_read_missing_query_functions()

    def test_write_valid(self):
        """
        Test that a Query request payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Query request payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.QueryRequestPayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_query_functions()

    def test_eq(self):
        """
        Test that two Query request payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Query request payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_query_functions()

class TestQueryResponsePayload(testtools.TestCase):
    """
    Test encodings obtained from Sections 12.1 and 12.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestQueryResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 12.1.0. Modified to include the Application
        # Namespaces.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Operations
        #         Create
        #         Create Key Pair
        #         Register
        #         Rekey
        #         Certify
        #         Recertify
        #         Locate
        #         Check
        #         Get
        #         Get Attributes
        #         Get Attribute List
        #         Add Attribute
        #         Modify Attribute
        #         Delete Attribute
        #         Obtain Lease
        #         Get Usage Allocation
        #         Activate
        #         Revoke
        #         Destroy
        #         Archive
        #         Recover
        #         Query
        #         Cancel
        #         Poll
        #         Rekey Key Pair
        #         Discover Versions
        #     Object Types
        #         Certificate
        #         Symmetric Key
        #         Public Key
        #         Private Key
        #         Template
        #         Secret Data
        #     Vendor Identification -
        #         IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1
        #     Server Information - empty
        #     Application Namespaces
        #         Namespace 1
        #         Namespace 2
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x02\x70'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x09\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0E\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0F\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x12\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x13\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x16\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x19\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1E\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x9D\x07\x00\x00\x00\x2E'
            b'\x49\x42\x4D\x20\x74\x65\x73\x74\x20\x73\x65\x72\x76\x65\x72\x2C'
            b'\x20\x6E\x6F\x74\x2D\x54\x4B\x4C\x4D\x20\x32\x2E\x30\x2E\x31\x2E'
            b'\x31\x20\x4B\x4D\x49\x50\x20\x32\x2E\x30\x2E\x30\x2E\x31\x00\x00'
            b'\x42\x00\x88\x01\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x32\x00\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 12.1.0. Modified to include the Application
        # Namespaces and Extension Information.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Operations
        #         Create
        #         Create Key Pair
        #         Register
        #         Rekey
        #         Certify
        #         Recertify
        #         Locate
        #         Check
        #         Get
        #         Get Attributes
        #         Get Attribute List
        #         Add Attribute
        #         Modify Attribute
        #         Delete Attribute
        #         Obtain Lease
        #         Get Usage Allocation
        #         Activate
        #         Revoke
        #         Destroy
        #         Archive
        #         Recover
        #         Query
        #         Cancel
        #         Poll
        #         Rekey Key Pair
        #         Discover Versions
        #     Object Types
        #         Certificate
        #         Symmetric Key
        #         Public Key
        #         Private Key
        #         Template
        #         Secret Data
        #     Vendor Identification -
        #         IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1
        #     Server Information - empty
        #     Application Namespaces
        #         Namespace 1
        #         Namespace 2
        #     Extension Information
        #         Extension Name - ACME LOCATION
        #         Extension Tag - 0x0054AA01
        #         Extension Type - 7
        #     Extension Information
        #         Extension Name - ACME ZIP CODE
        #         Extension Tag - 0x0054AA02
        #         Extension Type - 2
        self.full_encoding_kmip_1_1 = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x02\xF0'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x09\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0E\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0F\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x12\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x13\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x16\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x19\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1E\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x9D\x07\x00\x00\x00\x2E'
            b'\x49\x42\x4D\x20\x74\x65\x73\x74\x20\x73\x65\x72\x76\x65\x72\x2C'
            b'\x20\x6E\x6F\x74\x2D\x54\x4B\x4C\x4D\x20\x32\x2E\x30\x2E\x31\x2E'
            b'\x31\x20\x4B\x4D\x49\x50\x20\x32\x2E\x30\x2E\x30\x2E\x31\x00\x00'
            b'\x42\x00\x88\x01\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x32\x00\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x4C\x4F\x43\x41\x54\x49\x4F\x4E\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x01\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x5A\x49\x50\x20\x43\x4F\x44\x45\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x02\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 12.1.0. Modified to include the Application
        # Namespaces, Extension Information, and Attestation
        # Types.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Operations
        #         Create
        #         Create Key Pair
        #         Register
        #         Rekey
        #         Certify
        #         Recertify
        #         Locate
        #         Check
        #         Get
        #         Get Attributes
        #         Get Attribute List
        #         Add Attribute
        #         Modify Attribute
        #         Delete Attribute
        #         Obtain Lease
        #         Get Usage Allocation
        #         Activate
        #         Revoke
        #         Destroy
        #         Archive
        #         Recover
        #         Query
        #         Cancel
        #         Poll
        #         Rekey Key Pair
        #         Discover Versions
        #     Object Types
        #         Certificate
        #         Symmetric Key
        #         Public Key
        #         Private Key
        #         Template
        #         Secret Data
        #     Vendor Identification -
        #         IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1
        #     Server Information - empty
        #     Application Namespaces
        #         Namespace 1
        #         Namespace 2
        #     Extension Information
        #         Extension Name - ACME LOCATION
        #         Extension Tag - 0x0054AA01
        #         Extension Type - 7
        #     Extension Information
        #         Extension Name - ACME ZIP CODE
        #         Extension Tag - 0x0054AA02
        #         Extension Type - 2
        #     Attestation Types
        #         TPM Quote
        #         TCG Integrity Report
        #         SAML Assertion
        self.full_encoding_kmip_1_2 = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x03\x20'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x09\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0E\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0F\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x12\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x13\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x16\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x19\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1E\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x9D\x07\x00\x00\x00\x2E'
            b'\x49\x42\x4D\x20\x74\x65\x73\x74\x20\x73\x65\x72\x76\x65\x72\x2C'
            b'\x20\x6E\x6F\x74\x2D\x54\x4B\x4C\x4D\x20\x32\x2E\x30\x2E\x31\x2E'
            b'\x31\x20\x4B\x4D\x49\x50\x20\x32\x2E\x30\x2E\x30\x2E\x31\x00\x00'
            b'\x42\x00\x88\x01\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x32\x00\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x4C\x4F\x43\x41\x54\x49\x4F\x4E\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x01\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x5A\x49\x50\x20\x43\x4F\x44\x45\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x02\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 12.1.0. Modified to include the Application
        # Namespaces, Extension Information, Attestation Types,
        # RNG Parameters, Profile Information, Validation
        # Information, Capability Information, and Client
        # Registration Methods.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Operations
        #         Create
        #         Create Key Pair
        #         Register
        #         Rekey
        #         Certify
        #         Recertify
        #         Locate
        #         Check
        #         Get
        #         Get Attributes
        #         Get Attribute List
        #         Add Attribute
        #         Modify Attribute
        #         Delete Attribute
        #         Obtain Lease
        #         Get Usage Allocation
        #         Activate
        #         Revoke
        #         Destroy
        #         Archive
        #         Recover
        #         Query
        #         Cancel
        #         Poll
        #         Rekey Key Pair
        #         Discover Versions
        #     Object Types
        #         Certificate
        #         Symmetric Key
        #         Public Key
        #         Private Key
        #         Template
        #         Secret Data
        #     Vendor Identification -
        #         IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1
        #     Server Information - empty
        #     Application Namespaces
        #         Namespace 1
        #         Namespace 2
        #     Extension Information
        #         Extension Name - ACME LOCATION
        #         Extension Tag - 0x0054AA01
        #         Extension Type - 7
        #     Extension Information
        #         Extension Name - ACME ZIP CODE
        #         Extension Tag - 0x0054AA02
        #         Extension Type - 2
        #     Attestation Types
        #         TPM Quote
        #         TCG Integrity Report
        #         SAML Assertion
        #     RNGParameters
        #         RNG Algorithm - FIPS 186-2
        #         Cryptographic Algorithm - AES
        #         Cryptographic Length - 256
        #         Hashing Algorithm - SHA256
        #         DRBG Algorithm - Hash
        #         Recommended Curve - P-192
        #         FIPS186 Variation - GP x-Original
        #         Prediction Resistance - True
        #     Profile Information
        #         Profile Name - BASELINE_SERVER_BASIC_KMIPv12
        #         Server URI - https://example.com
        #         Server Port - 5696
        #     Validation Information
        #         Validation Authority Type - COMMON_CRITERIA
        #         Validation Authority Country - US
        #         Validation Authority URI - https://example.com
        #         Validation Version Major - 1
        #         Validation Version Minor - 0
        #         Validation Type - HYBRID
        #         Validation Level - 5
        #         Validation Certificate Identifier -
        #             c005d39e-604f-11e9-99df-080027fc1396
        #         Validation Certificate URI - https://test.com
        #         Validation Vendor URI - https://vendor.com
        #         Validation Profiles -
        #             Profile 1
        #             Profile 2
        #     Capability Information
        #         Streaming Capability - False
        #         Asynchronous Capability - True
        #         Attestation Capability - True
        #         Unwrap Mode - PROCESSED
        #         Destroy Action - SHREDDED
        #         Shredding Algorithm - CRYPTOGRAPHIC
        #         RNG Mode - NON_SHARED_INSTANTIATION
        #     Client Registration Methods
        #         Client Generated
        #         Client Registered
        self.full_encoding_kmip_1_3 = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x05\xA8'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x09\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0E\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0F\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x12\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x13\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x16\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x19\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1E\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x9D\x07\x00\x00\x00\x2E'
            b'\x49\x42\x4D\x20\x74\x65\x73\x74\x20\x73\x65\x72\x76\x65\x72\x2C'
            b'\x20\x6E\x6F\x74\x2D\x54\x4B\x4C\x4D\x20\x32\x2E\x30\x2E\x31\x2E'
            b'\x31\x20\x4B\x4D\x49\x50\x20\x32\x2E\x30\x2E\x30\x2E\x31\x00\x00'
            b'\x42\x00\x88\x01\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x32\x00\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x4C\x4F\x43\x41\x54\x49\x4F\x4E\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x01\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x5A\x49\x50\x20\x43\x4F\x44\x45\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x02\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xD9\x01\x00\x00\x00\x80'
            b'\x42\x00\xDA\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\xDB\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x75\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xDC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xDD\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xEB\x01\x00\x00\x00\x40'
            b'\x42\x00\xEC\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xED\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xEE\x02\x00\x00\x00\x04\x00\x00\x16\x40\x00\x00\x00\x00'
            b'\x42\x00\xDF\x01\x00\x00\x01\x18'
            b'\x42\x00\xE0\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xE1\x07\x00\x00\x00\x02\x55\x53\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE2\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xE3\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xE4\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE5\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE6\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE7\x07\x00\x00\x00\x24'
            b'\x63\x30\x30\x35\x64\x33\x39\x65\x2D\x36\x30\x34\x66\x2D\x31\x31'
            b'\x65\x39\x2D\x39\x39\x64\x66\x2D\x30\x38\x30\x30\x32\x37\x66\x63'
            b'\x31\x33\x39\x36\x00\x00\x00\x00'
            b'\x42\x00\xE8\x07\x00\x00\x00\x10'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x74\x65\x73\x74\x2E\x63\x6F\x6D'
            b'\x42\x00\xE9\x07\x00\x00\x00\x12'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x76\x65\x6E\x64\x6F\x72\x2E\x63'
            b'\x6F\x6D\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x31\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x32\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xF7\x01\x00\x00\x00\x70'
            b'\x42\x00\xEF\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xF0\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF1\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF2\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF3\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xF4\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF5\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xF6\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\xF6\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Section 12.1.0. Modified to include the Application
        # Namespaces, Extension Information, Attestation Types,
        # RNG Parameters, Profile Information, Validation
        # Information, Capability Information, Client
        # Registration Methods, Defaults Information, and Storage
        # Protection Masks.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Operations
        #         Create
        #         Create Key Pair
        #         Register
        #         Rekey
        #         Certify
        #         Recertify
        #         Locate
        #         Check
        #         Get
        #         Get Attributes
        #         Get Attribute List
        #         Add Attribute
        #         Modify Attribute
        #         Delete Attribute
        #         Obtain Lease
        #         Get Usage Allocation
        #         Activate
        #         Revoke
        #         Destroy
        #         Archive
        #         Recover
        #         Query
        #         Cancel
        #         Poll
        #         Rekey Key Pair
        #         Discover Versions
        #     Object Types
        #         Certificate
        #         Symmetric Key
        #         Public Key
        #         Private Key
        #         Template
        #         Secret Data
        #     Vendor Identification -
        #         IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1
        #     Server Information - empty
        #     Application Namespaces
        #         Namespace 1
        #         Namespace 2
        #     Extension Information
        #         Extension Name - ACME LOCATION
        #         Extension Tag - 0x0054AA01
        #         Extension Type - 7
        #     Extension Information
        #         Extension Name - ACME ZIP CODE
        #         Extension Tag - 0x0054AA02
        #         Extension Type - 2
        #     Attestation Types
        #         TPM Quote
        #         TCG Integrity Report
        #         SAML Assertion
        #     RNGParameters
        #         RNG Algorithm - FIPS 186-2
        #         Cryptographic Algorithm - AES
        #         Cryptographic Length - 256
        #         Hashing Algorithm - SHA256
        #         DRBG Algorithm - Hash
        #         Recommended Curve - P-192
        #         FIPS186 Variation - GP x-Original
        #         Prediction Resistance - True
        #     Profile Information
        #         Profile Name - BASELINE_SERVER_BASIC_KMIPv12
        #         Server URI - https://example.com
        #         Server Port - 5696
        #     Validation Information
        #         Validation Authority Type - COMMON_CRITERIA
        #         Validation Authority Country - US
        #         Validation Authority URI - https://example.com
        #         Validation Version Major - 1
        #         Validation Version Minor - 0
        #         Validation Type - HYBRID
        #         Validation Level - 5
        #         Validation Certificate Identifier -
        #             c005d39e-604f-11e9-99df-080027fc1396
        #         Validation Certificate URI - https://test.com
        #         Validation Vendor URI - https://vendor.com
        #         Validation Profiles -
        #             Profile 1
        #             Profile 2
        #     Capability Information
        #         Streaming Capability - False
        #         Asynchronous Capability - True
        #         Attestation Capability - True
        #         Unwrap Mode - PROCESSED
        #         Destroy Action - SHREDDED
        #         Shredding Algorithm - CRYPTOGRAPHIC
        #         RNG Mode - NON_SHARED_INSTANTIATION
        #     Client Registration Methods
        #         Client Generated
        #         Client Registered
        #     DefaultsInformation
        #         ObjectDefaults
        #             Object Type - Symmetric Key
        #             Attributes
        #                 Cryptographic Algorithm - AES
        #                 Cryptographic Length - 128
        #                 Cryptographic Usage Mask - Encrypt | Decrypt
        #     Protection Storage Mask - Software | Hardware
        self.full_encoding_kmip_2_0 = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x06\x10'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x09\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0B\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0E\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x0F\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x12\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x13\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x14\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x16\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x18\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x19\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1A\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1D\x00\x00\x00\x00'
            b'\x42\x00\x5C\x05\x00\x00\x00\x04\x00\x00\x00\x1E\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\x9D\x07\x00\x00\x00\x2E'
            b'\x49\x42\x4D\x20\x74\x65\x73\x74\x20\x73\x65\x72\x76\x65\x72\x2C'
            b'\x20\x6E\x6F\x74\x2D\x54\x4B\x4C\x4D\x20\x32\x2E\x30\x2E\x31\x2E'
            b'\x31\x20\x4B\x4D\x49\x50\x20\x32\x2E\x30\x2E\x30\x2E\x31\x00\x00'
            b'\x42\x00\x88\x01\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x31\x00\x00\x00\x00\x00'
            b'\x42\x00\x03\x07\x00\x00\x00\x0B'
            b'\x4E\x61\x6D\x65\x73\x70\x61\x63\x65\x20\x32\x00\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x4C\x4F\x43\x41\x54\x49\x4F\x4E\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x01\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xA4\x01\x00\x00\x00\x38'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D'
            b'\x41\x43\x4D\x45\x20\x5A\x49\x50\x20\x43\x4F\x44\x45\x00\x00\x00'
            b'\x42\x00\xA6\x02\x00\x00\x00\x04\x00\x54\xAA\x02\x00\x00\x00\x00'
            b'\x42\x00\xA7\x02\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xD9\x01\x00\x00\x00\x80'
            b'\x42\x00\xDA\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00'
            b'\x42\x00\x38\x05\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\x00\x00'
            b'\x42\x00\xDB\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x75\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xDC\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xDD\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xEB\x01\x00\x00\x00\x40'
            b'\x42\x00\xEC\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xED\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xEE\x02\x00\x00\x00\x04\x00\x00\x16\x40\x00\x00\x00\x00'
            b'\x42\x00\xDF\x01\x00\x00\x01\x18'
            b'\x42\x00\xE0\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xE1\x07\x00\x00\x00\x02\x55\x53\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE2\x07\x00\x00\x00\x13'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x65\x78\x61\x6D\x70\x6C\x65\x2E'
            b'\x63\x6F\x6D\x00\x00\x00\x00\x00'
            b'\x42\x00\xE3\x02\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xE4\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xE5\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE6\x02\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x00\xE7\x07\x00\x00\x00\x24'
            b'\x63\x30\x30\x35\x64\x33\x39\x65\x2D\x36\x30\x34\x66\x2D\x31\x31'
            b'\x65\x39\x2D\x39\x39\x64\x66\x2D\x30\x38\x30\x30\x32\x37\x66\x63'
            b'\x31\x33\x39\x36\x00\x00\x00\x00'
            b'\x42\x00\xE8\x07\x00\x00\x00\x10'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x74\x65\x73\x74\x2E\x63\x6F\x6D'
            b'\x42\x00\xE9\x07\x00\x00\x00\x12'
            b'\x68\x74\x74\x70\x73\x3A\x2F\x2F\x76\x65\x6E\x64\x6F\x72\x2E\x63'
            b'\x6F\x6D\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x31\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xEA\x07\x00\x00\x00\x09'
            b'\x50\x72\x6F\x66\x69\x6C\x65\x20\x32\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xF7\x01\x00\x00\x00\x70'
            b'\x42\x00\xEF\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xF0\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF1\x06\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x42\x00\xF2\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF3\x05\x00\x00\x00\x04\x00\x00\x00\x07\x00\x00\x00\x00'
            b'\x42\x00\xF4\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\xF5\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\xF6\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00'
            b'\x42\x00\xF6\x05\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00\x00'
            b'\x42\x01\x52\x01\x00\x00\x00\x50'
            b'\x42\x01\x53\x01\x00\x00\x00\x48'
            b'\x42\x00\x57\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x01\x25\x01\x00\x00\x00\x30'
            b'\x42\x00\x28\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x2A\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
            b'\x42\x00\x2C\x02\x00\x00\x00\x04\x00\x00\x00\x0C\x00\x00\x00\x00'
            b'\x42\x01\x5E\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
        )

        # This encoding matches the following set of values:
        # Response Payload
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestQueryResponsePayload, self).tearDown()

    def test_invalid_operations(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the operations of a Query response payload.
        """
        kwargs = {"operations": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The operations must be a list of Operation enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"operations": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The operations must be a list of Operation enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "operations",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The operations must be a list of Operation enumerations.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "operations",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The operations must be a list of Operation enumerations.",
            setattr,
            *args
        )

    def test_invalid_object_types(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the object types of a Query response payload.
        """
        kwargs = {"object_types": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The object types must be a list of ObjectType enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"object_types": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The object types must be a list of ObjectType enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "object_types",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The object types must be a list of ObjectType enumerations.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "object_types",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The object types must be a list of ObjectType enumerations.",
            setattr,
            *args
        )

    def test_invalid_vendor_identification(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the vendor identification of a Query response payload.
        """
        kwargs = {"vendor_identification": 0}
        self.assertRaisesRegex(
            TypeError,
            "The vendor identification must be a string.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "vendor_identification",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The vendor identification must be a string.",
            setattr,
            *args
        )

    def test_invalid_server_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the server information of a Query response payload.
        """
        kwargs = {"server_information": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The server information must be a ServerInformation structure.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "server_information",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The server information must be a ServerInformation structure.",
            setattr,
            *args
        )

    def test_invalid_application_namespaces(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the application namespaces of a Query response payload.
        """
        kwargs = {"application_namespaces": 0}
        self.assertRaisesRegex(
            TypeError,
            "The application namespaces must be a list of strings.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"application_namespaces": [0]}
        self.assertRaisesRegex(
            TypeError,
            "The application namespaces must be a list of strings.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "application_namespaces",
            0
        )
        self.assertRaisesRegex(
            TypeError,
            "The application namespaces must be a list of strings.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "application_namespaces",
            [0]
        )
        self.assertRaisesRegex(
            TypeError,
            "The application namespaces must be a list of strings.",
            setattr,
            *args
        )

    def test_invalid_extension_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the extension information of a Query response payload.
        """
        kwargs = {"extension_information": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The extension information must be a list of "
            "ExtensionInformation structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"extension_information": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The extension information must be a list of "
            "ExtensionInformation structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "extension_information",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The extension information must be a list of "
            "ExtensionInformation structures.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "extension_information",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The extension information must be a list of "
            "ExtensionInformation structures.",
            setattr,
            *args
        )

    def test_invalid_attestation_types(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attestation types of a Query response payload.
        """
        kwargs = {"attestation_types": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The attestation types must be a list of AttestationType "
            "enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"attestation_types": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The attestation types must be a list of AttestationType "
            "enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "attestation_types",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The attestation types must be a list of AttestationType "
            "enumerations.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "attestation_types",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The attestation types must be a list of AttestationType "
            "enumerations.",
            setattr,
            *args
        )

    def test_invalid_rng_parameters(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the RNG parameters of a Query response payload.
        """
        kwargs = {"rng_parameters": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The RNG parameters must be a list of RNGParameters structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"rng_parameters": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The RNG parameters must be a list of RNGParameters structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "rng_parameters",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The RNG parameters must be a list of RNGParameters structures.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "rng_parameters",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The RNG parameters must be a list of RNGParameters structures.",
            setattr,
            *args
        )

    def test_invalid_profile_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the profile information of a Query response payload.
        """
        kwargs = {"profile_information": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The profile information must be a list of ProfileInformation "
            "structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"profile_information": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The profile information must be a list of ProfileInformation "
            "structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "profile_information",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The profile information must be a list of ProfileInformation "
            "structures.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "profile_information",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The profile information must be a list of ProfileInformation "
            "structures.",
            setattr,
            *args
        )

    def test_invalid_validation_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the validation information of a Query response payload.
        """
        kwargs = {"validation_information": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The validation information must be a list of "
            "ValidationInformation structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"validation_information": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The validation information must be a list of "
            "ValidationInformation structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "validation_information",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation information must be a list of "
            "ValidationInformation structures.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "validation_information",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The validation information must be a list of "
            "ValidationInformation structures.",
            setattr,
            *args
        )

    def test_invalid_capability_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the capability information of a Query response payload.
        """
        kwargs = {"capability_information": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The capability information must be a list of "
            "CapabilityInformation structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"capability_information": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The capability information must be a list of "
            "CapabilityInformation structures.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "capability_information",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The capability information must be a list of "
            "CapabilityInformation structures.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "capability_information",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The capability information must be a list of "
            "CapabilityInformation structures.",
            setattr,
            *args
        )

    def test_invalid_client_registration_methods(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the client registration methods of a Query response payload.
        """
        kwargs = {"client_registration_methods": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The client registration methods must be a list of "
            "ClientRegistrationMethod enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"client_registration_methods": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The client registration methods must be a list of "
            "ClientRegistrationMethod enumerations.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "client_registration_methods",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The client registration methods must be a list of "
            "ClientRegistrationMethod enumerations.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "client_registration_methods",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The client registration methods must be a list of "
            "ClientRegistrationMethod enumerations.",
            setattr,
            *args
        )

    def test_invalid_defaults_information(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the defaults information of a Query response payload.
        """
        kwargs = {"defaults_information": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The defaults information must be a DefaultsInformation "
            "structure.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "defaults_information",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The defaults information must be a DefaultsInformation "
            "structure.",
            setattr,
            *args
        )

    def test_invalid_protection_storage_masks(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the protection storage masks of a Query response payload.
        """
        kwargs = {"protection_storage_masks": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers.",
            payloads.QueryResponsePayload,
            **kwargs
        )
        kwargs = {"protection_storage_masks": ["invalid"]}
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers.",
            payloads.QueryResponsePayload,
            **kwargs
        )

        args = (
            payloads.QueryResponsePayload(),
            "protection_storage_masks",
            "invalid"
        )
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers.",
            setattr,
            *args
        )
        args = (
            payloads.QueryResponsePayload(),
            "protection_storage_masks",
            ["invalid"]
        )
        self.assertRaisesRegex(
            TypeError,
            "The protection storage masks must be a list of integers.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a QueryResponsePayload structure can be correctly read in
        from a data stream.
        """
        payload = payloads.QueryResponsePayload()

        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)
        self.assertIsNone(payload.server_information)
        self.assertIsNone(payload.application_namespaces)

        payload.read(self.full_encoding)

        self.assertEqual(
            [
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            payload.operations
        )
        self.assertEqual(
            [
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            payload.object_types
        )
        self.assertEqual(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1",
            payload.vendor_identification
        )
        self.assertEqual(
            misc.ServerInformation(),
            payload.server_information
        )
        self.assertEqual(
            [
                "Namespace 1",
                "Namespace 2"
            ],
            payload.application_namespaces
        )

    def test_read_kmip_1_1(self):
        """
        Test that a QueryResponsePayload structure can be correctly read in
        from a data stream with KMIP 1.1 features.
        """
        payload = payloads.QueryResponsePayload()

        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)
        self.assertIsNone(payload.server_information)
        self.assertIsNone(payload.application_namespaces)
        self.assertIsNone(payload.extension_information)

        payload.read(
            self.full_encoding_kmip_1_1,
            kmip_version=enums.KMIPVersion.KMIP_1_1
        )

        self.assertEqual(
            [
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            payload.operations
        )
        self.assertEqual(
            [
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            payload.object_types
        )
        self.assertEqual(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1",
            payload.vendor_identification
        )
        self.assertEqual(
            misc.ServerInformation(),
            payload.server_information
        )
        self.assertEqual(
            [
                "Namespace 1",
                "Namespace 2"
            ],
            payload.application_namespaces
        )
        self.assertEqual(
            [
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            payload.extension_information
        )

    def test_read_kmip_1_2(self):
        """
        Test that a QueryResponsePayload structure can be correctly read in
        from a data stream with KMIP 1.2 features.
        """
        payload = payloads.QueryResponsePayload()

        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)
        self.assertIsNone(payload.server_information)
        self.assertIsNone(payload.application_namespaces)
        self.assertIsNone(payload.extension_information)
        self.assertIsNone(payload.attestation_types)

        payload.read(
            self.full_encoding_kmip_1_2,
            kmip_version=enums.KMIPVersion.KMIP_1_2
        )

        self.assertEqual(
            [
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            payload.operations
        )
        self.assertEqual(
            [
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            payload.object_types
        )
        self.assertEqual(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1",
            payload.vendor_identification
        )
        self.assertEqual(
            misc.ServerInformation(),
            payload.server_information
        )
        self.assertEqual(
            [
                "Namespace 1",
                "Namespace 2"
            ],
            payload.application_namespaces
        )
        self.assertEqual(
            [
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            payload.extension_information
        )
        self.assertEqual(
            [
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            payload.attestation_types
        )

    def test_read_kmip_1_3(self):
        """
        Test that a QueryResponsePayload structure can be correctly read in
        from a data stream with KMIP 1.3 features.
        """
        payload = payloads.QueryResponsePayload()

        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)
        self.assertIsNone(payload.server_information)
        self.assertIsNone(payload.application_namespaces)
        self.assertIsNone(payload.extension_information)
        self.assertIsNone(payload.attestation_types)
        self.assertIsNone(payload.rng_parameters)
        self.assertIsNone(payload.profile_information)
        self.assertIsNone(payload.validation_information)
        self.assertIsNone(payload.capability_information)
        self.assertIsNone(payload.client_registration_methods)

        payload.read(
            self.full_encoding_kmip_1_3,
            kmip_version=enums.KMIPVersion.KMIP_1_3
        )

        self.assertEqual(
            [
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            payload.operations
        )
        self.assertEqual(
            [
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            payload.object_types
        )
        self.assertEqual(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1",
            payload.vendor_identification
        )
        self.assertEqual(
            misc.ServerInformation(),
            payload.server_information
        )
        self.assertEqual(
            [
                "Namespace 1",
                "Namespace 2"
            ],
            payload.application_namespaces
        )
        self.assertEqual(
            [
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            payload.extension_information
        )
        self.assertEqual(
            [
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            payload.attestation_types
        )
        self.assertEqual(
            [
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            payload.rng_parameters
        )
        self.assertEqual(
            [
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            payload.profile_information
        )
        self.assertEqual(
            [
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            payload.validation_information
        )
        self.assertEqual(
            [
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            payload.capability_information
        )
        self.assertEqual(
            [
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            payload.client_registration_methods
        )

    def test_read_kmip_2_0(self):
        """
        Test that a QueryResponsePayload structure can be correctly read in
        from a data stream with KMIP 2.0 features.
        """
        payload = payloads.QueryResponsePayload()

        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)
        self.assertIsNone(payload.server_information)
        self.assertIsNone(payload.application_namespaces)
        self.assertIsNone(payload.extension_information)
        self.assertIsNone(payload.attestation_types)
        self.assertIsNone(payload.rng_parameters)
        self.assertIsNone(payload.profile_information)
        self.assertIsNone(payload.validation_information)
        self.assertIsNone(payload.capability_information)
        self.assertIsNone(payload.client_registration_methods)
        self.assertIsNone(payload.defaults_information)
        self.assertIsNone(payload.protection_storage_masks)

        payload.read(
            self.full_encoding_kmip_2_0,
            kmip_version=enums.KMIPVersion.KMIP_2_0
        )

        self.assertEqual(
            [
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            payload.operations
        )
        self.assertEqual(
            [
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            payload.object_types
        )
        self.assertEqual(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1",
            payload.vendor_identification
        )
        self.assertEqual(
            misc.ServerInformation(),
            payload.server_information
        )
        self.assertEqual(
            [
                "Namespace 1",
                "Namespace 2"
            ],
            payload.application_namespaces
        )
        self.assertEqual(
            [
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            payload.extension_information
        )
        self.assertEqual(
            [
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            payload.attestation_types
        )
        self.assertEqual(
            [
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            payload.rng_parameters
        )
        self.assertEqual(
            [
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            payload.profile_information
        )
        self.assertEqual(
            [
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            payload.validation_information
        )
        self.assertEqual(
            [
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            payload.capability_information
        )
        self.assertEqual(
            [
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            payload.client_registration_methods
        )
        self.assertEqual(
            objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            payload.defaults_information
        )
        self.assertEqual([3], payload.protection_storage_masks)

    def test_read_empty(self):
        """
        Test that an empty QueryResponsePayload structure can be correctly read
        in from a data stream.
        """
        payload = payloads.QueryResponsePayload()

        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)
        self.assertIsNone(payload.server_information)
        self.assertIsNone(payload.application_namespaces)

        payload.read(self.empty_encoding)

        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)
        self.assertIsNone(payload.server_information)
        self.assertIsNone(payload.application_namespaces)

    def test_write(self):
        """
        Test that a QueryResponsePayload structure can be written to a data
        stream.
        """
        payload = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ]
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.full_encoding), len(buffer))
        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_write_kmip_1_1(self):
        """
        Test that a QueryResponsePayload structure can be written to a data
        stream with KMIP 1.1 features.
        """
        payload = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ]
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_1_1)

        self.assertEqual(len(self.full_encoding_kmip_1_1), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_1_1), str(buffer))

    def test_write_kmip_1_2(self):
        """
        Test that a QueryResponsePayload structure can be written to a data
        stream with KMIP 1.2 features.
        """
        payload = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ]
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_1_2)

        self.assertEqual(len(self.full_encoding_kmip_1_2), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_1_2), str(buffer))

    def test_write_kmip_1_3(self):
        """
        Test that a QueryResponsePayload structure can be written to a data
        stream with KMIP 1.3 features.
        """
        payload = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ]
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_1_3)

        self.assertEqual(len(self.full_encoding_kmip_1_3), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_1_3), str(buffer))

    def test_write_kmip_2_0(self):
        """
        Test that a QueryResponsePayload structure can be written to a data
        stream with KMIP 2.0 features.
        """
        payload = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            protection_storage_masks=[3]
        )

        buffer = utils.BytearrayStream()
        payload.write(buffer, kmip_version=enums.KMIPVersion.KMIP_2_0)

        self.assertEqual(len(self.full_encoding_kmip_2_0), len(buffer))
        self.assertEqual(str(self.full_encoding_kmip_2_0), str(buffer))

    def test_write_empty(self):
        """
        Test that an empty QueryResponsePayload structure can be written to a
        data stream.
        """
        payload = payloads.QueryResponsePayload()

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(len(self.empty_encoding), len(buffer))
        self.assertEqual(str(self.empty_encoding), str(buffer))

    def test_repr(self):
        """
        Test that repr can be applied to a QueryResponsePayload structure.
        """
        payload = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            protection_storage_masks=[3]
        )

        operations = [
            "Operation.CREATE",
            "Operation.CREATE_KEY_PAIR",
            "Operation.REGISTER",
            "Operation.REKEY",
            "Operation.CERTIFY",
            "Operation.RECERTIFY",
            "Operation.LOCATE",
            "Operation.CHECK",
            "Operation.GET",
            "Operation.GET_ATTRIBUTES",
            "Operation.GET_ATTRIBUTE_LIST",
            "Operation.ADD_ATTRIBUTE",
            "Operation.MODIFY_ATTRIBUTE",
            "Operation.DELETE_ATTRIBUTE",
            "Operation.OBTAIN_LEASE",
            "Operation.GET_USAGE_ALLOCATION",
            "Operation.ACTIVATE",
            "Operation.REVOKE",
            "Operation.DESTROY",
            "Operation.ARCHIVE",
            "Operation.RECOVER",
            "Operation.QUERY",
            "Operation.CANCEL",
            "Operation.POLL",
            "Operation.REKEY_KEY_PAIR",
            "Operation.DISCOVER_VERSIONS"
        ]
        v = ", ".join(operations)
        ops = "operations=[{}]".format(v)

        object_types = [
            "ObjectType.CERTIFICATE",
            "ObjectType.SYMMETRIC_KEY",
            "ObjectType.PUBLIC_KEY",
            "ObjectType.PRIVATE_KEY",
            "ObjectType.TEMPLATE",
            "ObjectType.SECRET_DATA"
        ]
        v = ", ".join(object_types)
        ot = "object_types=[{}]".format(v)

        vei = 'vendor_identification="{}"'.format(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
        )

        sei = "server_information=ServerInformation()"

        an = 'application_namespaces=["{}", "{}"]'.format(
            "Namespace 1",
            "Namespace 2"
        )

        extensions = [
            objects.ExtensionInformation(
                extension_name=objects.ExtensionName("ACME LOCATION"),
                extension_tag=objects.ExtensionTag(0x0054AA01),
                extension_type=objects.ExtensionType(7)
            ),
            objects.ExtensionInformation(
                extension_name=objects.ExtensionName("ACME ZIP CODE"),
                extension_tag=objects.ExtensionTag(0x0054AA02),
                extension_type=objects.ExtensionType(2)
            )
        ]
        ei = "extension_information={}".format(repr(extensions))

        values = [
            "AttestationType.TPM_QUOTE",
            "AttestationType.TCG_INTEGRITY_REPORT",
            "AttestationType.SAML_ASSERTION"
        ]
        v = ", ".join(values)
        att = "attestation_types=[{}]".format(v)

        a = "rng_algorithm=RNGAlgorithm.FIPS186_2"
        c = "cryptographic_algorithm=CryptographicAlgorithm.AES"
        e = "cryptographic_length=256"
        h = "hashing_algorithm=HashingAlgorithm.SHA_256"
        d = "drbg_algorithm=DRBGAlgorithm.HASH"
        r = "recommended_curve=RecommendedCurve.P_192"
        f = "fips186_variation=FIPS186Variation.GP_X_ORIGINAL"
        p = "prediction_resistance=True"

        v = ", ".join([a, c, e, h, d, r, f, p])
        rp = "rng_parameters=[RNGParameters({})]".format(v)

        n = "profile_name=ProfileName.BASELINE_SERVER_BASIC_KMIPv12"
        u = 'server_uri="https://example.com"'
        p = "server_port=5696"

        v = ", ".join([n, u, p])
        pi = "profile_information=[ProfileInformation({})]".format(v)

        vat = "validation_authority_type=" + \
              "ValidationAuthorityType.COMMON_CRITERIA"
        vac = 'validation_authority_country="US"'
        vau = 'validation_authority_uri="https://example.com"'
        vvj = "validation_version_major=1"
        vvn = "validation_version_minor=0"
        vt = "validation_type=ValidationType.HYBRID"
        vl = "validation_level=5"
        vci = 'validation_certificate_identifier=' + \
              '"c005d39e-604f-11e9-99df-080027fc1396"'
        vcu = 'validation_certificate_uri="https://test.com"'
        vvu = 'validation_vendor_uri="https://vendor.com"'
        vp = 'validation_profiles=["Profile 1", "Profile 2"]'

        v = ", ".join([vat, vac, vau, vvj, vvn, vt, vl, vci, vcu, vvu, vp])
        vi = "validation_information=[ValidationInformation({})]".format(v)

        sc = "streaming_capability=False"
        rc = "asynchronous_capability=True"
        tc = "attestation_capability=True"
        buc = "batch_undo_capability=None"
        bcc = "batch_continue_capability=None"
        um = "unwrap_mode=UnwrapMode.PROCESSED"
        da = "destroy_action=DestroyAction.SHREDDED"
        sa = "shredding_algorithm=ShreddingAlgorithm.CRYPTOGRAPHIC"
        rm = "rng_mode=RNGMode.NON_SHARED_INSTANTIATION"

        v = ", ".join([sc, rc, tc, buc, bcc, um, da, sa, rm])
        ci = "capability_information=[CapabilityInformation({})]".format(v)

        m1 = "ClientRegistrationMethod.CLIENT_GENERATED"
        m2 = "ClientRegistrationMethod.CLIENT_REGISTERED"
        v = ", ".join([m1, m2])
        crm = "client_registration_methods=[{}]".format(v)

        o = "object_type=ObjectType.SYMMETRIC_KEY"
        a1e = "enum=CryptographicAlgorithm"
        a1v = "value=CryptographicAlgorithm.AES"
        a1t = "tag=Tags.CRYPTOGRAPHIC_ALGORITHM"
        a1a = ", ".join([a1e, a1v, a1t])
        a1 = "Enumeration({})".format(a1a)
        a2 = "Integer(value=128)"
        a3 = "Integer(value=12)"
        aa = ", ".join([a1, a2, a3])
        t = "tag=Tags.ATTRIBUTES"
        a = "attributes=Attributes(attributes=[{}], {})".format(aa, t)
        r = "ObjectDefaults({}, {})".format(o, a)
        d = "DefaultsInformation(object_defaults=[{}])".format(r)
        di = "defaults_information={}".format(d)

        psm = "protection_storage_masks=[3]"

        v = ", ".join(
            [ops, ot, vei, sei, an, ei, att, rp, pi, vi, ci, crm, di, psm]
        )

        self.assertEqual(
            "QueryResponsePayload({})".format(v),
            repr(payload)
        )

    def test_str(self):
        """
        Test that str can be applied to a QueryResponsePayload structure.
        """
        payload = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            protection_storage_masks=[3]
        )

        operations = [
            "Operation.CREATE",
            "Operation.CREATE_KEY_PAIR",
            "Operation.REGISTER",
            "Operation.REKEY",
            "Operation.CERTIFY",
            "Operation.RECERTIFY",
            "Operation.LOCATE",
            "Operation.CHECK",
            "Operation.GET",
            "Operation.GET_ATTRIBUTES",
            "Operation.GET_ATTRIBUTE_LIST",
            "Operation.ADD_ATTRIBUTE",
            "Operation.MODIFY_ATTRIBUTE",
            "Operation.DELETE_ATTRIBUTE",
            "Operation.OBTAIN_LEASE",
            "Operation.GET_USAGE_ALLOCATION",
            "Operation.ACTIVATE",
            "Operation.REVOKE",
            "Operation.DESTROY",
            "Operation.ARCHIVE",
            "Operation.RECOVER",
            "Operation.QUERY",
            "Operation.CANCEL",
            "Operation.POLL",
            "Operation.REKEY_KEY_PAIR",
            "Operation.DISCOVER_VERSIONS"
        ]
        v = ", ".join(operations)
        ops = '"operations": [{}]'.format(v)

        object_types = [
            "ObjectType.CERTIFICATE",
            "ObjectType.SYMMETRIC_KEY",
            "ObjectType.PUBLIC_KEY",
            "ObjectType.PRIVATE_KEY",
            "ObjectType.TEMPLATE",
            "ObjectType.SECRET_DATA"
        ]
        v = ", ".join(object_types)
        ot = '"object_types": [{}]'.format(v)

        vei = '"vendor_identification": "{}"'.format(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
        )

        sei = '"server_information": ServerInformation()'

        an = '"application_namespaces": ["{}", "{}"]'.format(
            "Namespace 1",
            "Namespace 2"
        )

        extensions = [
            objects.ExtensionInformation(
                extension_name=objects.ExtensionName("ACME LOCATION"),
                extension_tag=objects.ExtensionTag(0x0054AA01),
                extension_type=objects.ExtensionType(7)
            ),
            objects.ExtensionInformation(
                extension_name=objects.ExtensionName("ACME ZIP CODE"),
                extension_tag=objects.ExtensionTag(0x0054AA02),
                extension_type=objects.ExtensionType(2)
            )
        ]
        ei = '"extension_information": {}'.format(repr(extensions))

        values = [
            "AttestationType.TPM_QUOTE",
            "AttestationType.TCG_INTEGRITY_REPORT",
            "AttestationType.SAML_ASSERTION"
        ]
        v = ", ".join(values)
        att = '"attestation_types": [{}]'.format(v)

        a = '"rng_algorithm": RNGAlgorithm.FIPS186_2'
        c = '"cryptographic_algorithm": CryptographicAlgorithm.AES'
        e = '"cryptographic_length": 256'
        h = '"hashing_algorithm": HashingAlgorithm.SHA_256'
        d = '"drbg_algorithm": DRBGAlgorithm.HASH'
        r = '"recommended_curve": RecommendedCurve.P_192'
        f = '"fips186_variation": FIPS186Variation.GP_X_ORIGINAL'
        p = '"prediction_resistance": True'

        v = ", ".join([a, c, e, h, d, r, f, p])
        v = "{" + v + "}"
        rp = '"rng_parameters": [{}]'.format(v)

        n = '"profile_name": ProfileName.BASELINE_SERVER_BASIC_KMIPv12'
        u = '"server_uri": "https://example.com"'
        p = '"server_port": 5696'

        v = ", ".join([n, u, p])
        v = "{" + v + "}"
        pi = '"profile_information": [{}]'.format(v)

        vat = '"validation_authority_type": ' + \
              'ValidationAuthorityType.COMMON_CRITERIA'
        vac = '"validation_authority_country": "US"'
        vau = '"validation_authority_uri": "https://example.com"'
        vvj = '"validation_version_major": 1'
        vvn = '"validation_version_minor": 0'
        vt = '"validation_type": ValidationType.HYBRID'
        vl = '"validation_level": 5'
        vci = '"validation_certificate_identifier": ' + \
              '"c005d39e-604f-11e9-99df-080027fc1396"'
        vcu = '"validation_certificate_uri": "https://test.com"'
        vvu = '"validation_vendor_uri": "https://vendor.com"'
        vp = '"validation_profiles": ["Profile 1", "Profile 2"]'

        v = ", ".join([vat, vac, vau, vvj, vvn, vt, vl, vci, vcu, vvu, vp])
        v = "{" + v + "}"
        vi = '"validation_information": [{}]'.format(v)

        sc = '"streaming_capability": False'
        rc = '"asynchronous_capability": True'
        tc = '"attestation_capability": True'
        buc = '"batch_undo_capability": None'
        bcc = '"batch_continue_capability": None'
        um = '"unwrap_mode": UnwrapMode.PROCESSED'
        da = '"destroy_action": DestroyAction.SHREDDED'
        sa = '"shredding_algorithm": ShreddingAlgorithm.CRYPTOGRAPHIC'
        rm = '"rng_mode": RNGMode.NON_SHARED_INSTANTIATION'

        v = ", ".join([sc, rc, tc, buc, bcc, um, da, sa, rm])
        v = "{" + v + "}"
        ci = '"capability_information": [{}]'.format(v)

        m1 = "ClientRegistrationMethod.CLIENT_GENERATED"
        m2 = "ClientRegistrationMethod.CLIENT_REGISTERED"
        v = ", ".join([m1, m2])
        crm = '"client_registration_methods": [{}]'.format(v)

        o = '"object_type": ObjectType.SYMMETRIC_KEY'
        aa = '{"attributes": [CryptographicAlgorithm.AES, 128, 12]}'
        a = '"attributes": {}'.format(aa)
        r = "{" + "{}, {}".format(o, a) + "}"
        d = "{" + '"object_defaults": [' + r + "]}"
        di = '"defaults_information": {}'.format(d)

        psm = '"protection_storage_masks": [3]'

        v = ", ".join(
            [ops, ot, vei, sei, an, ei, att, rp, pi, vi, ci, crm, di, psm]
        )

        self.assertEqual("{" + v + "}", str(payload))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        QueryResponsePayload structures with the same data.
        """
        a = payloads.QueryResponsePayload()
        b = payloads.QueryResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            protection_storage_masks=[3]
        )
        b = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            protection_storage_masks=[3]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_operations(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different operations fields.
        """
        a = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ]
        )
        b = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_object_types(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different object types fields.
        """
        a = payloads.QueryResponsePayload(
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ]
        )
        b = payloads.QueryResponsePayload(
            object_types=[
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_vendor_identification(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different vendor identification
        fields.
        """
        a = payloads.QueryResponsePayload(
            vendor_identification="IBM test server, KMIP 2.0.0.1"
        )
        b = payloads.QueryResponsePayload(
            vendor_identification="IBM test server, KMIP 1.0.9.1"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_server_information(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different server information
        fields.
        """
        a = payloads.QueryResponsePayload(
            server_information=misc.ServerInformation()
        )
        b = payloads.QueryResponsePayload(
            server_information=None
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_application_namespaces(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different application namespaces
        fields.
        """
        a = payloads.QueryResponsePayload(
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ]
        )
        b = payloads.QueryResponsePayload(
            application_namespaces=["Namespace 3"]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_extension_information(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different extension information
        fields.
        """
        a = payloads.QueryResponsePayload(
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attestation_types(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different attestation types
        fields.
        """
        a = payloads.QueryResponsePayload(
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ]
        )
        b = payloads.QueryResponsePayload(
            attestation_types=[
                enums.AttestationType.TPM_QUOTE
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_rng_parameters(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different RNG parameters
        fields.
        """
        a = payloads.QueryResponsePayload(
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=128,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=False
                )
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_profile_information(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different profile information
        fields.
        """
        a = payloads.QueryResponsePayload(
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.TAPE_LIBRARY_SERVER_KMIPv12
                    ),
                    server_uri="https://test.com",
                    server_port=5696
                )
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_validation_information(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different validation information
        fields.
        """
        a = payloads.QueryResponsePayload(
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://authority.com",
                    validation_version_major=1,
                    validation_version_minor=1,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://certificate.com",
                    validation_vendor_uri="https://example.com",
                    validation_profiles=["Profile 3", "Profile 4"]
                )
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_capability_information(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different capability information
        fields.
        """
        a = payloads.QueryResponsePayload(
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=True,
                    asynchronous_capability=False,
                    attestation_capability=False,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_client_registration_methods(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different client registration
        methods fields.
        """
        a = payloads.QueryResponsePayload(
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ]
        )
        b = payloads.QueryResponsePayload(
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_defaults_information(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different defaults information
        fields.
        """
        a = payloads.QueryResponsePayload(
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            )
        )
        b = payloads.QueryResponsePayload(
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.PUBLIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.RSA,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=1024,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different protection storage
        masks fields.
        """
        a = payloads.QueryResponsePayload(protection_storage_masks=[3, 1])
        b = payloads.QueryResponsePayload(protection_storage_masks=[1, 2])

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        QueryResponsePayload structures with different types.
        """
        a = payloads.QueryResponsePayload()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        QueryResponsePayload structures with the same data.
        """
        a = payloads.QueryResponsePayload()
        b = payloads.QueryResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            protection_storage_masks=[3]
        )
        b = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ],
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ],
            vendor_identification=(
                "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1"
            ),
            server_information=misc.ServerInformation(),
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ],
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                ),
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ],
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ],
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ],
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ],
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ],
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ],
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ],
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            ),
            protection_storage_masks=[3]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_operations(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different operations fields.
        """
        a = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE,
                enums.Operation.MODIFY_ATTRIBUTE,
                enums.Operation.DELETE_ATTRIBUTE,
                enums.Operation.OBTAIN_LEASE,
                enums.Operation.GET_USAGE_ALLOCATION,
                enums.Operation.ACTIVATE,
                enums.Operation.REVOKE,
                enums.Operation.DESTROY,
                enums.Operation.ARCHIVE,
                enums.Operation.RECOVER,
                enums.Operation.QUERY,
                enums.Operation.CANCEL,
                enums.Operation.POLL,
                enums.Operation.REKEY_KEY_PAIR,
                enums.Operation.DISCOVER_VERSIONS
            ]
        )
        b = payloads.QueryResponsePayload(
            operations=[
                enums.Operation.CREATE,
                enums.Operation.CREATE_KEY_PAIR,
                enums.Operation.REGISTER,
                enums.Operation.REKEY,
                enums.Operation.CERTIFY,
                enums.Operation.RECERTIFY,
                enums.Operation.LOCATE,
                enums.Operation.CHECK,
                enums.Operation.GET,
                enums.Operation.GET_ATTRIBUTES,
                enums.Operation.GET_ATTRIBUTE_LIST,
                enums.Operation.ADD_ATTRIBUTE
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_object_types(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different object types fields.
        """
        a = payloads.QueryResponsePayload(
            object_types=[
                enums.ObjectType.CERTIFICATE,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ]
        )
        b = payloads.QueryResponsePayload(
            object_types=[
                enums.ObjectType.PRIVATE_KEY,
                enums.ObjectType.TEMPLATE,
                enums.ObjectType.SECRET_DATA
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_vendor_identification(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different vendor identification
        fields.
        """
        a = payloads.QueryResponsePayload(
            vendor_identification="IBM test server, KMIP 2.0.0.1"
        )
        b = payloads.QueryResponsePayload(
            vendor_identification="IBM test server, KMIP 1.0.9.1"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_server_information(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different server information
        fields.
        """
        a = payloads.QueryResponsePayload(
            server_information=misc.ServerInformation()
        )
        b = payloads.QueryResponsePayload(
            server_information=None
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_application_namespaces(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different application namespaces
        fields.
        """
        a = payloads.QueryResponsePayload(
            application_namespaces=[
                "Namespace 1",
                "Namespace 2"
            ]
        )
        b = payloads.QueryResponsePayload(
            application_namespaces=["Namespace 3"]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_extension_information(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different extension information
        fields.
        """
        a = payloads.QueryResponsePayload(
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME LOCATION"),
                    extension_tag=objects.ExtensionTag(0x0054AA01),
                    extension_type=objects.ExtensionType(7)
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            extension_information=[
                objects.ExtensionInformation(
                    extension_name=objects.ExtensionName("ACME ZIP CODE"),
                    extension_tag=objects.ExtensionTag(0x0054AA02),
                    extension_type=objects.ExtensionType(2)
                )
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attestation_types(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different attestation types
        fields.
        """
        a = payloads.QueryResponsePayload(
            attestation_types=[
                enums.AttestationType.TPM_QUOTE,
                enums.AttestationType.TCG_INTEGRITY_REPORT,
                enums.AttestationType.SAML_ASSERTION
            ]
        )
        b = payloads.QueryResponsePayload(
            attestation_types=[
                enums.AttestationType.TPM_QUOTE
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_rng_parameters(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different RNG parameters
        fields.
        """
        a = payloads.QueryResponsePayload(
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=256,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=True
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            rng_parameters=[
                objects.RNGParameters(
                    rng_algorithm=enums.RNGAlgorithm.FIPS186_2,
                    cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
                    cryptographic_length=128,
                    hashing_algorithm=enums.HashingAlgorithm.SHA_256,
                    drbg_algorithm=enums.DRBGAlgorithm.HASH,
                    recommended_curve=enums.RecommendedCurve.P_192,
                    fips186_variation=enums.FIPS186Variation.GP_X_ORIGINAL,
                    prediction_resistance=False
                )
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_profile_information(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different profile information
        fields.
        """
        a = payloads.QueryResponsePayload(
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.BASELINE_SERVER_BASIC_KMIPv12
                    ),
                    server_uri="https://example.com",
                    server_port=5696
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            profile_information=[
                objects.ProfileInformation(
                    profile_name=(
                        enums.ProfileName.TAPE_LIBRARY_SERVER_KMIPv12
                    ),
                    server_uri="https://test.com",
                    server_port=5696
                )
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_validation_information(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different validation information
        fields.
        """
        a = payloads.QueryResponsePayload(
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://example.com",
                    validation_version_major=1,
                    validation_version_minor=0,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://test.com",
                    validation_vendor_uri="https://vendor.com",
                    validation_profiles=["Profile 1", "Profile 2"]
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            validation_information=[
                objects.ValidationInformation(
                    validation_authority_type=(
                        enums.ValidationAuthorityType.COMMON_CRITERIA
                    ),
                    validation_authority_country="US",
                    validation_authority_uri="https://authority.com",
                    validation_version_major=1,
                    validation_version_minor=1,
                    validation_type=enums.ValidationType.HYBRID,
                    validation_level=5,
                    validation_certificate_identifier=(
                        "c005d39e-604f-11e9-99df-080027fc1396"
                    ),
                    validation_certificate_uri="https://certificate.com",
                    validation_vendor_uri="https://example.com",
                    validation_profiles=["Profile 3", "Profile 4"]
                )
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_capability_information(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different capability information
        fields.
        """
        a = payloads.QueryResponsePayload(
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=False,
                    asynchronous_capability=True,
                    attestation_capability=True,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ]
        )
        b = payloads.QueryResponsePayload(
            capability_information=[
                objects.CapabilityInformation(
                    streaming_capability=True,
                    asynchronous_capability=False,
                    attestation_capability=False,
                    unwrap_mode=enums.UnwrapMode.PROCESSED,
                    destroy_action=enums.DestroyAction.SHREDDED,
                    shredding_algorithm=enums.ShreddingAlgorithm.CRYPTOGRAPHIC,
                    rng_mode=enums.RNGMode.NON_SHARED_INSTANTIATION
                )
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_client_registration_methods(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different client registration
        methods fields.
        """
        a = payloads.QueryResponsePayload(
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED,
                enums.ClientRegistrationMethod.CLIENT_REGISTERED
            ]
        )
        b = payloads.QueryResponsePayload(
            client_registration_methods=[
                enums.ClientRegistrationMethod.CLIENT_GENERATED
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_defaults_information(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different defaults information
        fields.
        """
        a = payloads.QueryResponsePayload(
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.SYMMETRIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.AES,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=128,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value |
                                        enums.CryptographicUsageMask.DECRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            )
        )
        b = payloads.QueryResponsePayload(
            defaults_information=objects.DefaultsInformation(
                object_defaults=[
                    objects.ObjectDefaults(
                        object_type=enums.ObjectType.PUBLIC_KEY,
                        attributes=objects.Attributes(
                            attributes=[
                                primitives.Enumeration(
                                    enums.CryptographicAlgorithm,
                                    value=enums.CryptographicAlgorithm.RSA,
                                    tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                                ),
                                primitives.Integer(
                                    value=1024,
                                    tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                                ),
                                primitives.Integer(
                                    value=(
                                        enums.CryptographicUsageMask.ENCRYPT.
                                        value
                                    ),
                                    tag=enums.Tags.CRYPTOGRAPHIC_USAGE_MASK
                                )
                            ]
                        )
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_protection_storage_masks(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different protection storage
        masks fields.
        """
        a = payloads.QueryResponsePayload(protection_storage_masks=[3, 1])
        b = payloads.QueryResponsePayload(protection_storage_masks=[1, 2])

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        QueryResponsePayload structures with different types.
        """
        a = payloads.QueryResponsePayload()
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_init(self):
        """
        Test that a Query response payload can be constructed with no
        arguments.
        """
        payload = payloads.QueryResponsePayload()
        self.assertIsNone(payload.operations)
        self.assertIsNone(payload.object_types)
        self.assertIsNone(payload.vendor_identification)

    def test_init_with_args(self):
        """
        Test that a Query response payload can be constructed with valid
        values.
        """
        payload = payloads.QueryResponsePayload(
            operations=[enums.Operation.CREATE],
            object_types=[enums.ObjectType.SYMMETRIC_KEY],
            vendor_identification="ExampleVendor"
        )

        self.assertEqual([enums.Operation.CREATE], payload.operations)
        self.assertEqual(
            [enums.ObjectType.SYMMETRIC_KEY],
            payload.object_types
        )
        self.assertEqual("ExampleVendor", payload.vendor_identification)

    def test_read_valid(self):
        """
        Test that a Query response payload can be read from a valid byte
        stream.
        """
        self.test_read()

    def test_read_missing_required_field(self):
        """
        Test that an exception is raised when reading a payload missing a
        required field.
        """
        payload = payloads.QueryResponsePayload()
        self.assertRaises(Exception, payload.read, utils.BytearrayStream(b""))

    def test_write_valid(self):
        """
        Test that a Query response payload can be written to a byte stream.
        """
        self.test_write()

    def test_read_write_roundtrip(self):
        """
        Test that a Query response payload can be read and written without
        changing the encoded bytes.
        """
        payload = payloads.QueryResponsePayload()
        payload.read(utils.BytearrayStream(self.full_encoding.buffer))

        buffer = utils.BytearrayStream()
        payload.write(buffer)

        self.assertEqual(str(self.full_encoding), str(buffer))

    def test_validate_invalid(self):
        """
        Test that an exception is raised when a field has an invalid type.
        """
        self.test_invalid_operations()

    def test_eq(self):
        """
        Test that two Query response payloads with the same data are equal.
        """
        self.test_equal_on_equal()

    def test_ne(self):
        """
        Test that two Query response payloads with different data are not
        equal.
        """
        self.test_not_equal_on_not_equal_operations()
