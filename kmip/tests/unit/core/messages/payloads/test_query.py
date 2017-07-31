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

from six.moves import xrange

from testtools import TestCase

from kmip.core import utils

from kmip.core.attributes import ObjectType

from kmip.core.enums import ObjectType as ObjectTypeEnum
from kmip.core.enums import Operation as OperationEnum
from kmip.core.enums import QueryFunction as QueryFunctionEnum

from kmip.core.messages.contents import Operation
from kmip.core.messages import payloads

from kmip.core.misc import QueryFunction
from kmip.core.misc import VendorIdentification
from kmip.core.misc import ServerInformation

from kmip.core.objects import ExtensionInformation
from kmip.core.objects import ExtensionName


class TestQueryRequestPayload(TestCase):
    """
    Test suite for the QueryRequestPayload class.

    Test encodings obtained from Sections 12.1 and 12.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestQueryRequestPayload, self).setUp()

        self.query_functions_a = list()
        self.query_functions_b = list()
        self.query_functions_c = list()

        self.query_functions_b.append(QueryFunction(
            QueryFunctionEnum.QUERY_OPERATIONS))
        self.query_functions_b.append(QueryFunction(
            QueryFunctionEnum.QUERY_OBJECTS))
        self.query_functions_b.append(QueryFunction(
            QueryFunctionEnum.QUERY_SERVER_INFORMATION))

        self.query_functions_c.append(QueryFunction(
            QueryFunctionEnum.QUERY_EXTENSION_LIST))

        self.encoding_a = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x00'))

        self.encoding_b = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x30\x42\x00\x74\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x74\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x74\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x03\x00\x00\x00\x00'))

        self.encoding_c = utils.BytearrayStream((
            b'\x42\x00\x79\x01\x00\x00\x00\x10\x42\x00\x74\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x05\x00\x00\x00\x00'))

    def tearDown(self):
        super(TestQueryRequestPayload, self).tearDown()

    def test_init_with_none(self):
        """
        Test that a QueryRequestPayload object can be constructed with no
        specified value.
        """
        payloads.QueryRequestPayload()

    def test_init_with_args(self):
        """
        Test that a QueryRequestPayload object can be constructed with valid
        values.
        """
        payloads.QueryRequestPayload(self.query_functions_a)
        payloads.QueryRequestPayload(self.query_functions_b)
        payloads.QueryRequestPayload(self.query_functions_c)

    def test_validate_with_invalid_query_functions_list(self):
        """
        Test that a TypeError exception is raised when an invalid QueryFunction
        list is used to construct a QueryRequestPayload object.
        """
        kwargs = {'query_functions': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "invalid query functions list",
            payloads.QueryRequestPayload, **kwargs)

    def test_validate_with_invalid_query_functions_item(self):
        """
        Test that a TypeError exception is raised when an invalid QueryFunction
        item is used to construct a QueryRequestPayload object.
        """
        kwargs = {'query_functions': ['invalid']}
        self.assertRaisesRegexp(
            TypeError, "invalid query function",
            payloads.QueryRequestPayload, **kwargs)

    def _test_read(self, stream, query_functions):
        payload = payloads.QueryRequestPayload()
        payload.read(stream)
        expected = len(query_functions)
        observed = len(payload.query_functions)

        msg = "query functions list decoding mismatch"
        msg += "; expected {0} results, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

        for i in xrange(len(query_functions)):
            expected = query_functions[i]
            observed = payload.query_functions[i]

            msg = "query function decoding mismatch"
            msg += "; expected {0}, received {1}".format(expected, observed)
            self.assertEqual(expected, observed, msg)

    def test_read_with_empty_query_functions_list(self):
        """
        Test that a QueryRequestPayload object with no data can be read from
        a data stream.
        """
        self._test_read(self.encoding_a, self.query_functions_a)

    def test_read_with_multiple_query_functions(self):
        """
        Test that a QueryRequestPayload object with multiple pieces of data
        can be read from a data stream.
        """
        self._test_read(self.encoding_b, self.query_functions_b)

    def test_read_with_one_query_function(self):
        """
        Test that a QueryRequestPayload object with a single piece of data can
        be read from a data stream.
        """
        self._test_read(self.encoding_c, self.query_functions_c)

    def _test_write(self, encoding, query_functions):
        stream = utils.BytearrayStream()
        payload = payloads.QueryRequestPayload(query_functions)
        payload.write(stream)

        length_expected = len(encoding)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(encoding, stream)

        self.assertEqual(encoding, stream, msg)

    def test_write_with_empty_query_functions_list(self):
        """
        Test that a QueryRequestPayload object with no data can be written to
        a data stream.
        """
        self._test_write(self.encoding_a, self.query_functions_a)

    def test_write_with_multiple_query_functions(self):
        """
        Test that a QueryRequestPayload object with multiple pieces of data
        can be written to a data stream.
        """
        self._test_write(self.encoding_b, self.query_functions_b)

    def test_write_with_one_query_function(self):
        """
        Test that a QueryRequestPayload object with a single piece of data can
        be written to a data stream.
        """
        self._test_write(self.encoding_c, self.query_functions_c)


class TestQueryResponsePayload(TestCase):
    """
    Test encodings obtained from Sections 12.1 and 12.2 of the KMIP 1.1 Test
    Cases documentation.
    """

    def setUp(self):
        super(TestQueryResponsePayload, self).setUp()

        self.operations = list()
        self.object_types = list()
        self.application_namespaces = list()
        self.extension_information = list()

        self.vendor_identification = VendorIdentification(
            "IBM test server, not-TKLM 2.0.1.1 KMIP 2.0.0.1")
        self.server_information = ServerInformation()

        self.operations.append(Operation(OperationEnum.CREATE))
        self.operations.append(Operation(OperationEnum.CREATE_KEY_PAIR))
        self.operations.append(Operation(OperationEnum.REGISTER))
        self.operations.append(Operation(OperationEnum.REKEY))
        self.operations.append(Operation(OperationEnum.CERTIFY))
        self.operations.append(Operation(OperationEnum.RECERTIFY))
        self.operations.append(Operation(OperationEnum.LOCATE))
        self.operations.append(Operation(OperationEnum.CHECK))
        self.operations.append(Operation(OperationEnum.GET))
        self.operations.append(Operation(OperationEnum.GET_ATTRIBUTES))
        self.operations.append(Operation(OperationEnum.GET_ATTRIBUTE_LIST))
        self.operations.append(Operation(OperationEnum.ADD_ATTRIBUTE))
        self.operations.append(Operation(OperationEnum.MODIFY_ATTRIBUTE))
        self.operations.append(Operation(OperationEnum.DELETE_ATTRIBUTE))
        self.operations.append(Operation(OperationEnum.OBTAIN_LEASE))
        self.operations.append(Operation(OperationEnum.GET_USAGE_ALLOCATION))
        self.operations.append(Operation(OperationEnum.ACTIVATE))
        self.operations.append(Operation(OperationEnum.REVOKE))
        self.operations.append(Operation(OperationEnum.DESTROY))
        self.operations.append(Operation(OperationEnum.ARCHIVE))
        self.operations.append(Operation(OperationEnum.RECOVER))
        self.operations.append(Operation(OperationEnum.QUERY))
        self.operations.append(Operation(OperationEnum.CANCEL))
        self.operations.append(Operation(OperationEnum.POLL))
        self.operations.append(Operation(OperationEnum.REKEY_KEY_PAIR))
        self.operations.append(Operation(OperationEnum.DISCOVER_VERSIONS))

        self.object_types.append(ObjectType(ObjectTypeEnum.CERTIFICATE))
        self.object_types.append(ObjectType(ObjectTypeEnum.SYMMETRIC_KEY))
        self.object_types.append(ObjectType(ObjectTypeEnum.PUBLIC_KEY))
        self.object_types.append(ObjectType(ObjectTypeEnum.PRIVATE_KEY))
        self.object_types.append(ObjectType(ObjectTypeEnum.TEMPLATE))
        self.object_types.append(ObjectType(ObjectTypeEnum.SECRET_DATA))

        self.extension_information.append(ExtensionInformation(
            extension_name=ExtensionName("ACME LOCATION")))
        self.extension_information.append(ExtensionInformation(
            extension_name=ExtensionName("ACME ZIP CODE")))

        self.encoding_a = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'))

        self.encoding_b = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x02\x40\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x03\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x04\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x06\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x07\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x08\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x09\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x0A\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x0B\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x0C\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x0D\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x0E\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x0F\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x10\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x11\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x12\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x13\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x14\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x15\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x16\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x18\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x19\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x1A\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x1D\x00\x00\x00\x00\x42\x00\x5C\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x1E\x00\x00\x00\x00\x42\x00\x57\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x01\x00\x00\x00\x00\x42\x00\x57\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x02\x00\x00\x00\x00\x42\x00\x57\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x03\x00\x00\x00\x00\x42\x00\x57\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x04\x00\x00\x00\x00\x42\x00\x57\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x06\x00\x00\x00\x00\x42\x00\x57\x05\x00\x00\x00\x04'
            b'\x00\x00\x00\x07\x00\x00\x00\x00\x42\x00\x9D\x07\x00\x00\x00\x2E'
            b'\x49\x42\x4D\x20\x74\x65\x73\x74\x20\x73\x65\x72\x76\x65\x72\x2C'
            b'\x20\x6E\x6F\x74\x2D\x54\x4B\x4C\x4D\x20\x32\x2E\x30\x2E\x31\x2E'
            b'\x31\x20\x4B\x4D\x49\x50\x20\x32\x2E\x30\x2E\x30\x2E\x31\x00\x00'
            b'\x42\x00\x88\x01\x00\x00\x00\x00'))

        self.encoding_c = utils.BytearrayStream((
            b'\x42\x00\x7C\x01\x00\x00\x00\x40\x42\x00\xA4\x01\x00\x00\x00\x18'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D\x41\x43\x4D\x45\x20\x4C\x4F\x43'
            b'\x41\x54\x49\x4F\x4E\x00\x00\x00\x42\x00\xA4\x01\x00\x00\x00\x18'
            b'\x42\x00\xA5\x07\x00\x00\x00\x0D\x41\x43\x4D\x45\x20\x5A\x49\x50'
            b'\x20\x43\x4F\x44\x45\x00\x00\x00'))

    def tearDown(self):
        super(TestQueryResponsePayload, self).tearDown()

    def test_init_with_none(self):
        """
        Test that a QueryResponsePayload object can be constructed with no
        specified value.
        """
        payloads.QueryResponsePayload()

    def test_init_with_args(self):
        """
        Test that a QueryResponsePayload object can be constructed with valid
        values.
        """
        payloads.QueryResponsePayload(
            operations=self.operations,
            object_types=self.object_types,
            vendor_identification=self.vendor_identification,
            server_information=self.server_information,
            application_namespaces=self.application_namespaces,
            extension_information=self.extension_information)

    def test_validate_with_invalid_operations_list(self):
        """
        Test that a TypeError exception is raised when an invalid Operations
        list is used to construct a QueryResponsePayload object.
        """
        kwargs = {'operations': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "invalid operations list",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_operations_item(self):
        """
        Test that a TypeError exception is raised when an invalid Operations
        item is used to construct a QueryResponsePayload object.
        """
        kwargs = {'operations': ['invalid']}
        self.assertRaisesRegexp(
            TypeError, "invalid operation",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_object_types_list(self):
        """
        Test that a TypeError exception is raised when an invalid ObjectTypes
        list is used to construct a QueryResponsePayload object.
        """
        kwargs = {'object_types': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "invalid object types list",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_object_types_item(self):
        """
        Test that a TypeError exception is raised when an invalid ObjectTypes
        item is used to construct a QueryResponsePayload object.
        """
        kwargs = {'object_types': ['invalid']}
        self.assertRaisesRegexp(
            TypeError, "invalid object type",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_vendor_identification(self):
        """
        Test that a TypeError exception is raised when an invalid
        VendorIdentification item is used to construct a QueryResponsePayload
        object.
        """
        kwargs = {'vendor_identification': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "invalid vendor identification",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_server_information(self):
        """
        Test that a TypeError exception is raised when an invalid
        ServerInformation item is used to construct a QueryResponsePayload
        object.
        """
        kwargs = {'server_information': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "invalid server information",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_application_namespaces_list(self):
        """
        Test that a TypeError exception is raised when an invalid
        ApplicationNamespaces list is used to construct a QueryResponsePayload
        object.
        """
        kwargs = {'application_namespaces': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "invalid application namespaces list",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_application_namespaces_item(self):
        """
        Test that a TypeError exception is raised when an invalid
        ApplicationNamespaces item is used to construct a QueryResponsePayload
        object.
        """
        kwargs = {'application_namespaces': ['invalid']}
        self.assertRaisesRegexp(
            TypeError, "invalid application namespace",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_extension_information_list(self):
        """
        Test that a TypeError exception is raised when an invalid
        ExtensionInformation list is used to construct a QueryResponsePayload
        object.
        """
        kwargs = {'extension_information': 'invalid'}
        self.assertRaisesRegexp(
            TypeError, "invalid extension information list",
            payloads.QueryResponsePayload, **kwargs)

    def test_validate_with_invalid_extension_information_item(self):
        """
        Test that a TypeError exception is raised when an invalid
        ExtensionInformation item is used to construct a QueryResponsePayload
        object.
        """
        kwargs = {'extension_information': ['invalid']}
        self.assertRaisesRegexp(
            TypeError, "invalid extension information",
            payloads.QueryResponsePayload, **kwargs)

    def _test_read(self, stream, operations, object_types,
                   vendor_identification, server_information,
                   application_namespaces, extension_information):
        payload = payloads.QueryResponsePayload()
        payload.read(stream)

        # Test decoding of all operations.
        expected = len(operations)
        observed = len(payload.operations)

        msg = "operations list decoding mismatch"
        msg += "; expected {0} results, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

        for i in xrange(len(operations)):
            expected = operations[i]
            observed = payload.operations[i]

            msg = "operation decoding mismatch"
            msg += "; expected {0}, received {1}".format(expected, observed)
            self.assertEqual(expected, observed, msg)

        # Test decoding of all object types.
        expected = len(object_types)
        observed = len(payload.object_types)

        msg = "object types list decoding mismatch"
        msg += "; expected {0} results, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

        for i in xrange(len(object_types)):
            expected = object_types[i]
            observed = payload.object_types[i]

            msg = "object type decoding mismatch"
            msg += "; expected {0}, received {1}".format(expected, observed)
            self.assertEqual(expected, observed, msg)

        # Test decoding of vendor identification.
        expected = vendor_identification
        observed = payload.vendor_identification

        msg = "vendor identification decoding mismatch"
        msg += "; expected {0}, received {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        # Test decoding of server information.
        expected = server_information
        observed = payload.server_information

        msg = "server information decoding mismatch"
        msg += "; expected {0}, received {1}".format(expected, observed)
        self.assertEqual(expected, observed, msg)

        # Test decoding of all application namespaces.
        expected = len(application_namespaces)
        observed = len(payload.application_namespaces)

        msg = "application namespaces list decoding mismatch"
        msg += "; expected {0} results, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

        # Test decoding of all extension information.
        expected = len(extension_information)
        observed = len(payload.extension_information)

        msg = "extension information list decoding mismatch"
        msg += "; expected {0} results, received {1}".format(
            expected, observed)
        self.assertEqual(expected, observed, msg)

        for i in xrange(len(extension_information)):
            expected = extension_information[i]
            observed = payload.extension_information[i]

            msg = "extension information decoding mismatch"
            msg += "; expected {0}, received {1}".format(expected, observed)
            self.assertEqual(expected, observed, msg)

    def test_read_with_no_data(self):
        """
        Test that a QueryResponsePayload object with no data can be read from
        a data stream.
        """
        self._test_read(
            self.encoding_a, list(), list(), None, None, list(), list())

    def test_read_with_operations_object_types_and_server_info(self):
        """
        Test that a QueryResponsePayload object with multiple pieces of data
        can be read from a data stream.
        """
        self._test_read(
            self.encoding_b, self.operations, self.object_types,
            self.vendor_identification, self.server_information,
            self.application_namespaces, list())

    def test_read_with_extension_information(self):
        """
        Test that a QueryResponsePayload object with one piece of data can be
        read from a data stream.
        """
        self._test_read(
            self.encoding_c, list(), list(), None, None,
            self.application_namespaces, self.extension_information)

    def _test_write(self, encoding, operations, object_types,
                    vendor_identification, server_information,
                    application_namespaces, extension_information):
        stream = utils.BytearrayStream()
        payload = payloads.QueryResponsePayload(
            operations, object_types, vendor_identification,
            server_information, application_namespaces, extension_information)
        payload.write(stream)

        length_expected = len(encoding)
        length_received = len(stream)

        msg = "encoding lengths not equal"
        msg += "; expected {0}, received {1}".format(
            length_expected, length_received)
        self.assertEqual(length_expected, length_received, msg)

        msg = "encoding mismatch"
        msg += ";\nexpected:\n{0}\nreceived:\n{1}".format(encoding, stream)

        self.assertEqual(encoding, stream, msg)

    def test_write_with_no_data(self):
        """
        Test that a QueryResponsePayload object with no data can be written to
        a data stream.
        """
        self._test_write(
            self.encoding_a, list(), list(), None, None, list(), list())

    def test_write_with_operations_object_types_and_server_info(self):
        """
        Test that a QueryResponsePayload object with multiple pieces of data
        can be written to a data stream.
        """
        self._test_write(
            self.encoding_b, self.operations, self.object_types,
            self.vendor_identification, self.server_information,
            self.application_namespaces, list())

    def test_write_with_extension_information(self):
        """
        Test that a QueryResponsePayload object with one piece of data can be
        written to a data stream.
        """
        self._test_write(
            self.encoding_c, list(), list(), None, None,
            self.application_namespaces, self.extension_information)
