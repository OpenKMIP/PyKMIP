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

from kmip.core.attributes import ApplicationNamespace
from kmip.core.attributes import ObjectType

from kmip.core.enums import Tags
from kmip.core.messages.contents import Operation

from kmip.core.misc import QueryFunction
from kmip.core.misc import ServerInformation
from kmip.core.misc import VendorIdentification

from kmip.core.objects import ExtensionInformation
from kmip.core.primitives import Struct
from kmip.core.utils import BytearrayStream


class QueryRequestPayload(Struct):
    """
    A request payload for the Query operation.

    The payload contains a list of query functions that the KMIP server should
    respond to. See Section 4.25 of the KMIP 1.1 specification for more
    information.

    Attributes:
        query_functions: A list of QueryFunction enumerations.
    """
    def __init__(self, query_functions=None):
        """
        Construct a QueryRequestPayload object.

        Args:
            query_functions (list): A list of QueryFunction enumerations.
        """
        super(QueryRequestPayload, self).__init__(Tags.REQUEST_PAYLOAD)

        if query_functions is None:
            self.query_functions = list()
        else:
            self.query_functions = query_functions

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the QueryRequestPayload object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(QueryRequestPayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        while(self.is_tag_next(Tags.QUERY_FUNCTION, tstream)):
            query_function = QueryFunction()
            query_function.read(tstream)
            self.query_functions.append(query_function)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the QueryRequestPayload object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        for query_function in self.query_functions:
            query_function.write(tstream)

        self.length = tstream.length()
        super(QueryRequestPayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the QueryRequestPayload object.
        """
        self.__validate()

    def __validate(self):
        if isinstance(self.query_functions, list):
            for i in xrange(len(self.query_functions)):
                query_function = self.query_functions[i]
                if not isinstance(query_function, QueryFunction):
                    msg = "invalid query function ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        QueryFunction, query_function)
                    raise TypeError(msg)
        else:
            msg = "invalid query functions list"
            msg += "; expected {0}, received {1}".format(
                list, self.query_functions)
            raise TypeError(msg)


class QueryResponsePayload(Struct):
    """
    A response payload for the Query operation.

    The payload contains different sets of responses that the KMIP server
    provides in response to the initial Query request. See Section 4.25 of the
    KMIP 1.1 specification for more information.

    Attributes:
        operations: A list of Operations supported by the server.
        object_types: A list of ObjectTypes supported by the server.
        vendor_identification: A string identifying the server vendor.
        server_information: A structure containing vendor-specific fields and
            substructures.
        application_namespaces: A list of application namespaces supported by
            the server.
        extension_information: A list of ExtensionInformation objects detailing
            Objects supported by the server with ItemTag values in the
            Extensions range.
    """
    def __init__(self, operations=None, object_types=None,
                 vendor_identification=None, server_information=None,
                 application_namespaces=None, extension_information=None):
        """
        Construct a QueryResponsePayload object.

        Args:
            operations (list): A list of Operations supported by the server.
            object_types (list): A list of ObjectTypes supported by the server.
            vendor_identification (VendorIdentification): A string identifying
                the server vendor.
            server_information (ServerInformation): A structure containing
                vendor-specific fields and substructures.
            application_namespaces (list): A list of application namespaces
                supported by the server.
            extension_information (list): A list of ExtensionInformation
                objects detailing Objects supported by the server with ItemTag
                values in the Extensions range.
        """
        super(QueryResponsePayload, self).__init__(Tags.RESPONSE_PAYLOAD)

        if operations is None:
            self.operations = list()
        else:
            self.operations = operations

        if object_types is None:
            self.object_types = list()
        else:
            self.object_types = object_types

        self.vendor_identification = vendor_identification
        self.server_information = server_information

        if application_namespaces is None:
            self.application_namespaces = list()
        else:
            self.application_namespaces = application_namespaces

        if extension_information is None:
            self.extension_information = list()
        else:
            self.extension_information = extension_information

        self.validate()

    def read(self, istream):
        """
        Read the data encoding the QueryResponsePayload object and decode it
        into its constituent parts.

        Args:
            istream (Stream): A data stream containing encoded object data,
                supporting a read method; usually a BytearrayStream object.
        """
        super(QueryResponsePayload, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        while(self.is_tag_next(Tags.OPERATION, tstream)):
            operation = Operation()
            operation.read(tstream)
            self.operations.append(operation)

        while(self.is_tag_next(Tags.OBJECT_TYPE, tstream)):
            object_type = ObjectType()
            object_type.read(tstream)
            self.object_types.append(object_type)

        if self.is_tag_next(Tags.VENDOR_IDENTIFICATION, tstream):
            self.vendor_identification = VendorIdentification()
            self.vendor_identification.read(tstream)

        if self.is_tag_next(Tags.SERVER_INFORMATION, tstream):
            self.server_information = ServerInformation()
            self.server_information.read(tstream)

        while(self.is_tag_next(Tags.APPLICATION_NAMESPACE, tstream)):
            application_namespace = ApplicationNamespace()
            application_namespace.read(tstream)
            self.application_namespaces.append(application_namespace)

        while(self.is_tag_next(Tags.EXTENSION_INFORMATION, tstream)):
            extension_information = ExtensionInformation()
            extension_information.read(tstream)
            self.extension_information.append(extension_information)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        """
        Write the data encoding the QueryResponsePayload object to a stream.

        Args:
            ostream (Stream): A data stream in which to encode object data,
                supporting a write method; usually a BytearrayStream object.
        """
        tstream = BytearrayStream()

        for operation in self.operations:
            operation.write(tstream)

        for object_type in self.object_types:
            object_type.write(tstream)

        if self.vendor_identification is not None:
            self.vendor_identification.write(tstream)

        if self.server_information is not None:
            self.server_information.write(tstream)

        for application_namespace in self.application_namespaces:
            application_namespace.write(tstream)

        for extension_information in self.extension_information:
            extension_information.write(tstream)

        self.length = tstream.length()
        super(QueryResponsePayload, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        """
        Error check the attributes of the QueryRequestPayload object.
        """
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Add separate validate_list function for this
        if isinstance(self.operations, list):
            for i in xrange(len(self.operations)):
                operation = self.operations[i]
                if not isinstance(operation, Operation):
                    msg = "invalid operation ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        Operation, operation)
                    raise TypeError(msg)
        else:
            msg = "invalid operations list"
            msg += "; expected {0}, received {1}".format(
                list, self.operations)
            raise TypeError(msg)

        if isinstance(self.object_types, list):
            for i in xrange(len(self.object_types)):
                object_type = self.object_types[i]
                if not isinstance(object_type, ObjectType):
                    msg = "invalid object type ({0} in list)".format(i)
                    msg += "; expected {0}, received {1}".format(
                        ObjectType, object_type)
                    raise TypeError(msg)
        else:
            msg = "invalid object types list"
            msg += "; expected {0}, received {1}".format(
                list, self.object_types)
            raise TypeError(msg)

        if self.vendor_identification is not None:
            if not isinstance(self.vendor_identification,
                              VendorIdentification):
                msg = "invalid vendor identification"
                msg += "; expected {0}, received {1}".format(
                    VendorIdentification, self.vendor_identification)
                raise TypeError(msg)

        if self.server_information is not None:
            if not isinstance(self.server_information, ServerInformation):
                msg = "invalid server information"
                msg += "; expected {0}, received {1}".format(
                    ServerInformation, self.server_information)
                raise TypeError(msg)

        if isinstance(self.application_namespaces, list):
            for i in xrange(len(self.application_namespaces)):
                application_namespace = self.application_namespaces[i]
                if not isinstance(application_namespace, ApplicationNamespace):
                    msg = "invalid application namespace ({0} in list)".format(
                        i)
                    msg += "; expected {0}, received {1}".format(
                        ApplicationNamespace, application_namespace)
                    raise TypeError(msg)
        else:
            msg = "invalid application namespaces list"
            msg += "; expected {0}, received {1}".format(
                list, self.application_namespaces)
            raise TypeError(msg)

        if isinstance(self.extension_information, list):
            for i in xrange(len(self.extension_information)):
                extension_information = self.extension_information[i]
                if not isinstance(extension_information, ExtensionInformation):
                    msg = "invalid extension information ({0} in list)".format(
                        i)
                    msg += "; expected {0}, received {1}".format(
                        ExtensionInformation, extension_information)
                    raise TypeError(msg)
        else:
            msg = "invalid extension information list"
            msg += "; expected {0}, received {1}".format(
                list, self.extension_information)
            raise TypeError(msg)
