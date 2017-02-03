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

from kmip.services.results import ActivateResult
from kmip.services.results import CreateResult
from kmip.services.results import CreateKeyPairResult
from kmip.services.results import DestroyResult
from kmip.services.results import DiscoverVersionsResult
from kmip.services.results import GetResult
from kmip.services.results import GetAttributesResult
from kmip.services.results import GetAttributeListResult
from kmip.services.results import LocateResult
from kmip.services.results import OperationResult
from kmip.services.results import QueryResult
from kmip.services.results import RegisterResult
from kmip.services.results import RekeyKeyPairResult
from kmip.services.results import RevokeResult
from kmip.services.results import MACResult

from kmip.core import attributes as attr

from kmip.core.enums import AuthenticationSuite
from kmip.core.enums import ConformanceClause
from kmip.core.enums import CredentialType
from kmip.core.enums import Operation as OperationEnum

from kmip.core.factories.credentials import CredentialFactory

from kmip.core import objects
from kmip.core.server import KMIP

from kmip.core.messages.contents import Authentication
from kmip.core.messages.contents import BatchCount
from kmip.core.messages.contents import Operation
from kmip.core.messages.contents import ProtocolVersion

from kmip.core.messages import messages

from kmip.core.messages.payloads import activate
from kmip.core.messages.payloads import create
from kmip.core.messages.payloads import create_key_pair
from kmip.core.messages.payloads import destroy
from kmip.core.messages.payloads import discover_versions
from kmip.core.messages.payloads import get
from kmip.core.messages.payloads import get_attributes
from kmip.core.messages.payloads import get_attribute_list
from kmip.core.messages.payloads import locate
from kmip.core.messages.payloads import query
from kmip.core.messages.payloads import rekey_key_pair
from kmip.core.messages.payloads import register
from kmip.core.messages.payloads import revoke
from kmip.core.messages.payloads import mac

from kmip.services.server.kmip_protocol import KMIPProtocol

from kmip.core.config_helper import ConfigHelper

from kmip.core.utils import BytearrayStream

import logging
import logging.config
import os
import socket
import ssl

FILE_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.normpath(os.path.join(FILE_PATH, '../kmipconfig.ini'))


class KMIPProxy(KMIP):

    def __init__(self, host=None, port=None, keyfile=None,
                 certfile=None,
                 cert_reqs=None, ssl_version=None, ca_certs=None,
                 do_handshake_on_connect=None,
                 suppress_ragged_eofs=None,
                 username=None, password=None, timeout=30, config='client'):
        super(KMIPProxy, self).__init__()
        self.logger = logging.getLogger(__name__)
        self.credential_factory = CredentialFactory()
        self.config = config

        self._set_variables(host, port, keyfile, certfile,
                            cert_reqs, ssl_version, ca_certs,
                            do_handshake_on_connect, suppress_ragged_eofs,
                            username, password, timeout)
        self.batch_items = []

        self.conformance_clauses = [
            ConformanceClause.DISCOVER_VERSIONS]

        self.authentication_suites = [
            AuthenticationSuite.BASIC,
            AuthenticationSuite.TLS12]
        self.socket = None

    def get_supported_conformance_clauses(self):
        """
        Get the list of conformance clauses supported by the client.

        Returns:
            list: A shallow copy of the list of supported conformance clauses.

        Example:
            >>> client.get_supported_conformance_clauses()
            [<ConformanceClause.DISCOVER_VERSIONS: 1>]
        """
        return self.conformance_clauses[:]

    def get_supported_authentication_suites(self):
        """
        Get the list of authentication suites supported by the client.

        Returns:
            list: A shallow copy of the list of supported authentication
                suites.

        Example:
            >>> client.get_supported_authentication_suites()
            [<AuthenticationSuite.BASIC: 1>, <AuthenticationSuite.TLS12: 2>]
        """
        return self.authentication_suites[:]

    def is_conformance_clause_supported(self, conformance_clause):
        """
        Check if a ConformanceClause is supported by the client.

        Args:
            conformance_clause (ConformanceClause): A ConformanceClause
                enumeration to check against the list of supported
                ConformanceClauses.

        Returns:
            bool: True if the ConformanceClause is supported, False otherwise.

        Example:
            >>> clause = ConformanceClause.DISCOVER_VERSIONS
            >>> client.is_conformance_clause_supported(clause)
            True
            >>> clause = ConformanceClause.BASELINE
            >>> client.is_conformance_clause_supported(clause)
            False
        """
        return conformance_clause in self.conformance_clauses

    def is_authentication_suite_supported(self, authentication_suite):
        """
        Check if an AuthenticationSuite is supported by the client.

        Args:
            authentication_suite (AuthenticationSuite): An AuthenticationSuite
                enumeration to check against the list of supported
                AuthenticationSuites.

        Returns:
            bool: True if the AuthenticationSuite is supported, False
                otherwise.

        Example:
            >>> suite = AuthenticationSuite.BASIC
            >>> client.is_authentication_suite_supported(suite)
            True
            >>> suite = AuthenticationSuite.TLS12
            >>> client.is_authentication_suite_supported(suite)
            False
        """
        return authentication_suite in self.authentication_suites

    def is_profile_supported(self, conformance_clause, authentication_suite):
        """
        Check if a profile is supported by the client.

        Args:
            conformance_clause (ConformanceClause):
            authentication_suite (AuthenticationSuite):

        Returns:
            bool: True if the profile is supported, False otherwise.

        Example:
            >>> client.is_profile_supported(
            ... ConformanceClause.DISCOVER_VERSIONS,
            ... AuthenticationSuite.BASIC)
            True
        """
        return (self.is_conformance_clause_supported(conformance_clause) and
                self.is_authentication_suite_supported(authentication_suite))

    def open(self):

        self.logger.debug("KMIPProxy keyfile: {0}".format(self.keyfile))
        self.logger.debug("KMIPProxy certfile: {0}".format(self.certfile))
        self.logger.debug(
            "KMIPProxy cert_reqs: {0} (CERT_REQUIRED: {1})".format(
                self.cert_reqs, ssl.CERT_REQUIRED))
        self.logger.debug(
            "KMIPProxy ssl_version: {0} (PROTOCOL_SSLv23: {1})".format(
                self.ssl_version, ssl.PROTOCOL_SSLv23))
        self.logger.debug("KMIPProxy ca_certs: {0}".format(self.ca_certs))
        self.logger.debug("KMIPProxy do_handshake_on_connect: {0}".format(
            self.do_handshake_on_connect))
        self.logger.debug("KMIPProxy suppress_ragged_eofs: {0}".format(
            self.suppress_ragged_eofs))

        last_error = None

        for host in self.host_list:
            self.host = host
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._create_socket(sock)
            self.protocol = KMIPProtocol(self.socket)
            try:
                self.socket.connect((self.host, self.port))
            except Exception as e:
                self.logger.error("An error occurred while connecting to "
                                  "appliance " + self.host)
                self.socket.close()
                last_error = e
            else:
                return

        self.socket = None
        if last_error:
            raise last_error

    def _create_socket(self, sock):
        self.socket = ssl.wrap_socket(
            sock,
            keyfile=self.keyfile,
            certfile=self.certfile,
            cert_reqs=self.cert_reqs,
            ssl_version=self.ssl_version,
            ca_certs=self.ca_certs,
            do_handshake_on_connect=self.do_handshake_on_connect,
            suppress_ragged_eofs=self.suppress_ragged_eofs)
        self.socket.settimeout(self.timeout)

    def __del__(self):
        # Close the socket properly, helpful in case close() is not called.
        self.close()

    def close(self):
        # Shutdown and close the socket.
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except OSError:
                # Can be thrown if the socket is not actually connected to
                # anything. In this case, ignore the error.
                pass
            self.socket = None

    def create(self, object_type, template_attribute, credential=None):
        object_type = attr.ObjectType(object_type)
        return self._create(object_type=object_type,
                            template_attribute=template_attribute,
                            credential=credential)

    def create_key_pair(self, batch=False, common_template_attribute=None,
                        private_key_template_attribute=None,
                        public_key_template_attribute=None, credential=None):
        batch_item = self._build_create_key_pair_batch_item(
            common_template_attribute, private_key_template_attribute,
            public_key_template_attribute)

        if batch:
            self.batch_items.append(batch_item)
        else:
            request = self._build_request_message(credential, [batch_item])
            response = self._send_and_receive_message(request)
            results = self._process_batch_items(response)
            return results[0]

    def activate(self, uuid=None, credential=None):
        """
        Send an Activate request to the server.

        Args:
            uuid (string): The unique identifier of a managed cryptographic
                object that should be activated.
            credential (Credential): A Credential object containing
                authentication information for the server. Optional, defaults
                to None.
        """
        return self._activate(uuid, credential=credential)

    def get(self, uuid=None, key_format_type=None, key_compression_type=None,
            key_wrapping_specification=None, credential=None):
        return self._get(
            unique_identifier=uuid,
            key_format_type=key_format_type,
            key_compression_type=key_compression_type,
            key_wrapping_specification=key_wrapping_specification,
            credential=credential)

    def get_attributes(self, uuid=None, attribute_names=None):
        """
        Send a GetAttributes request to the server.

        Args:
            uuid (string): The ID of the managed object with which the
                retrieved attributes should be associated. Optional, defaults
                to None.
            attribute_names (list): A list of AttributeName values indicating
                what object attributes the client wants from the server.
                Optional, defaults to None.

        Returns:
            result (GetAttributesResult): A structure containing the results
                of the operation.
        """
        batch_item = self._build_get_attributes_batch_item(
            uuid,
            attribute_names
        )

        request = self._build_request_message(None, [batch_item])
        response = self._send_and_receive_message(request)
        results = self._process_batch_items(response)
        return results[0]

    def get_attribute_list(self, uid=None):
        """
        Send a GetAttributeList request to the server.

        Args:
            uid (string): The ID of the managed object with which the retrieved
                attribute names should be associated.

        Returns:
            result (GetAttributeListResult): A structure containing the results
                of the operation.
        """
        batch_item = self._build_get_attribute_list_batch_item(uid)

        request = self._build_request_message(None, [batch_item])
        response = self._send_and_receive_message(request)
        results = self._process_batch_items(response)
        return results[0]

    def revoke(self, uuid, reason, message=None, credential=None):
        return self._revoke(unique_identifier=uuid,
                            revocation_code=reason,
                            revocation_message=message,
                            credential=credential)

    def destroy(self, uuid, credential=None):
        return self._destroy(unique_identifier=uuid,
                             credential=credential)

    def register(self, object_type, template_attribute, secret,
                 credential=None):
        object_type = attr.ObjectType(object_type)
        return self._register(object_type=object_type,
                              template_attribute=template_attribute,
                              secret=secret,
                              credential=credential)

    def rekey_key_pair(self, batch=False, private_key_uuid=None, offset=None,
                       common_template_attribute=None,
                       private_key_template_attribute=None,
                       public_key_template_attribute=None, credential=None):
        batch_item = self._build_rekey_key_pair_batch_item(
            private_key_uuid, offset, common_template_attribute,
            private_key_template_attribute, public_key_template_attribute)

        if batch:
            self.batch_items.append(batch_item)
        else:
            request = self._build_request_message(credential, [batch_item])
            response = self._send_and_receive_message(request)
            results = self._process_batch_items(response)
            return results[0]

    def locate(self, maximum_items=None, storage_status_mask=None,
               object_group_member=None, attributes=None, credential=None):
        return self._locate(maximum_items=maximum_items,
                            storage_status_mask=storage_status_mask,
                            object_group_member=object_group_member,
                            attributes=attributes, credential=credential)

    def query(self, batch=False, query_functions=None, credential=None):
        """
        Send a Query request to the server.

        Args:
            batch (boolean): A flag indicating if the operation should be sent
                with a batch of additional operations. Defaults to False.
            query_functions (list): A list of QueryFunction enumerations
                indicating what information the client wants from the server.
                Optional, defaults to None.
            credential (Credential): A Credential object containing
                authentication information for the server. Optional, defaults
                to None.
        """
        batch_item = self._build_query_batch_item(query_functions)

        # TODO (peter-hamilton): Replace this with official client batch mode.
        if batch:
            self.batch_items.append(batch_item)
        else:
            request = self._build_request_message(credential, [batch_item])
            response = self._send_and_receive_message(request)
            results = self._process_batch_items(response)
            return results[0]

    def discover_versions(self, batch=False, protocol_versions=None,
                          credential=None):
        batch_item = self._build_discover_versions_batch_item(
            protocol_versions)

        if batch:
            self.batch_items.append(batch_item)
        else:
            request = self._build_request_message(credential, [batch_item])
            response = self._send_and_receive_message(request)
            results = self._process_batch_items(response)
            return results[0]

    def mac(self, unique_identifier=None, cryptographic_parameters=None,
            data=None, credential=None):
        return self._mac(
            unique_identifier=unique_identifier,
            cryptographic_parameters=cryptographic_parameters,
            data=data,
            credential=credential)

    def _create(self,
                object_type=None,
                template_attribute=None,
                credential=None):
        operation = Operation(OperationEnum.CREATE)

        if object_type is None:
            raise ValueError('object_type cannot be None')

        req_pl = create.CreateRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            payload_unique_identifier = None
            payload_template_attribute = None
            payload_object_type = None
        else:
            payload_unique_identifier = payload.unique_identifier
            payload_template_attribute = payload.template_attribute
            payload_object_type = payload.object_type

        result = CreateResult(batch_item.result_status,
                              batch_item.result_reason,
                              batch_item.result_message,
                              payload_object_type,
                              payload_unique_identifier,
                              payload_template_attribute)
        return result

    def _build_create_key_pair_batch_item(self, common_template_attribute=None,
                                          private_key_template_attribute=None,
                                          public_key_template_attribute=None):
        operation = Operation(OperationEnum.CREATE_KEY_PAIR)
        payload = create_key_pair.CreateKeyPairRequestPayload(
            common_template_attribute=common_template_attribute,
            private_key_template_attribute=private_key_template_attribute,
            public_key_template_attribute=public_key_template_attribute)
        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _build_rekey_key_pair_batch_item(self,
                                         private_key_uuid=None, offset=None,
                                         common_template_attribute=None,
                                         private_key_template_attribute=None,
                                         public_key_template_attribute=None):
        operation = Operation(OperationEnum.REKEY_KEY_PAIR)
        payload = rekey_key_pair.RekeyKeyPairRequestPayload(
            private_key_uuid, offset,
            common_template_attribute=common_template_attribute,
            private_key_template_attribute=private_key_template_attribute,
            public_key_template_attribute=public_key_template_attribute)
        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _build_query_batch_item(self, query_functions=None):
        operation = Operation(OperationEnum.QUERY)
        payload = query.QueryRequestPayload(query_functions)
        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _build_get_attributes_batch_item(
            self,
            uuid=None,
            attribute_names=None
    ):
        operation = Operation(OperationEnum.GET_ATTRIBUTES)
        payload = get_attributes.GetAttributesRequestPayload(
            uuid,
            attribute_names
        )
        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=payload
        )
        return batch_item

    def _build_get_attribute_list_batch_item(self, uid=None):
        operation = Operation(OperationEnum.GET_ATTRIBUTE_LIST)
        payload = get_attribute_list.GetAttributeListRequestPayload(uid)
        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _build_discover_versions_batch_item(self, protocol_versions=None):
        operation = Operation(OperationEnum.DISCOVER_VERSIONS)

        payload = discover_versions.DiscoverVersionsRequestPayload(
            protocol_versions)

        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _process_batch_items(self, response):
        results = []
        for batch_item in response.batch_items:
            operation = None
            if batch_item.operation is not None:
                operation = batch_item.operation.value
            processor = self._get_batch_item_processor(operation)
            result = processor(batch_item)
            results.append(result)
        return results

    def _get_batch_item_processor(self, operation):
        if operation is None:
            return self._process_response_error
        elif operation == OperationEnum.CREATE_KEY_PAIR:
            return self._process_create_key_pair_batch_item
        elif operation == OperationEnum.GET_ATTRIBUTES:
            return self._process_get_attributes_batch_item
        elif operation == OperationEnum.GET_ATTRIBUTE_LIST:
            return self._process_get_attribute_list_batch_item
        elif operation == OperationEnum.REKEY_KEY_PAIR:
            return self._process_rekey_key_pair_batch_item
        elif operation == OperationEnum.QUERY:
            return self._process_query_batch_item
        elif operation == OperationEnum.DISCOVER_VERSIONS:
            return self._process_discover_versions_batch_item
        else:
            raise ValueError("no processor for operation: {0}".format(
                operation))

    def _process_get_attributes_batch_item(self, batch_item):
        payload = batch_item.response_payload

        uuid = None
        attributes = None

        if payload:
            uuid = payload.unique_identifier
            attributes = payload.attributes

        return GetAttributesResult(
            batch_item.result_status,
            batch_item.result_reason,
            batch_item.result_message,
            uuid,
            attributes
        )

    def _process_get_attribute_list_batch_item(self, batch_item):
        payload = batch_item.response_payload

        uid = None
        names = None

        if payload:
            uid = payload.uid
            names = payload.attribute_names

        return GetAttributeListResult(
            batch_item.result_status,
            batch_item.result_reason,
            batch_item.result_message,
            uid,
            names)

    def _process_key_pair_batch_item(self, batch_item, result):
        payload = batch_item.response_payload

        payload_private_key_uuid = None
        payload_public_key_uuid = None
        payload_private_key_template_attribute = None
        payload_public_key_template_attribute = None

        if payload is not None:
            payload_private_key_uuid = payload.private_key_uuid
            payload_public_key_uuid = payload.public_key_uuid
            payload_private_key_template_attribute = \
                payload.private_key_template_attribute
            payload_public_key_template_attribute = \
                payload.public_key_template_attribute

        return result(batch_item.result_status, batch_item.result_reason,
                      batch_item.result_message, payload_private_key_uuid,
                      payload_public_key_uuid,
                      payload_private_key_template_attribute,
                      payload_public_key_template_attribute)

    def _process_create_key_pair_batch_item(self, batch_item):
        return self._process_key_pair_batch_item(
            batch_item, CreateKeyPairResult)

    def _process_rekey_key_pair_batch_item(self, batch_item):
        return self._process_key_pair_batch_item(
            batch_item, RekeyKeyPairResult)

    def _process_query_batch_item(self, batch_item):
        payload = batch_item.response_payload

        operations = None
        object_types = None
        vendor_identification = None
        server_information = None
        application_namespaces = None
        extension_information = None

        if payload is not None:
            operations = payload.operations
            object_types = payload.object_types
            vendor_identification = payload.vendor_identification
            server_information = payload.server_information
            application_namespaces = payload.application_namespaces
            extension_information = payload.extension_information

        return QueryResult(
            batch_item.result_status,
            batch_item.result_reason,
            batch_item.result_message,
            operations,
            object_types,
            vendor_identification,
            server_information,
            application_namespaces,
            extension_information)

    def _process_discover_versions_batch_item(self, batch_item):
        payload = batch_item.response_payload

        result = DiscoverVersionsResult(
            batch_item.result_status, batch_item.result_reason,
            batch_item.result_message, payload.protocol_versions)

        return result

    def _process_response_error(self, batch_item):
        result = OperationResult(
            batch_item.result_status, batch_item.result_reason,
            batch_item.result_message)
        return result

    def _get(self,
             unique_identifier=None,
             key_format_type=None,
             key_compression_type=None,
             key_wrapping_specification=None,
             credential=None):
        operation = Operation(OperationEnum.GET)

        uuid = None
        kft = None
        kct = None
        kws = None

        if unique_identifier is not None:
            uuid = attr.UniqueIdentifier(unique_identifier)
        if key_format_type is not None:
            kft = get.GetRequestPayload.KeyFormatType(key_format_type.value)
        if key_compression_type is not None:
            kct = key_compression_type
            kct = get.GetRequestPayload.KeyCompressionType(kct)
        if key_wrapping_specification is not None:
            kws = objects.KeyWrappingSpecification(key_wrapping_specification)

        req_pl = get.GetRequestPayload(unique_identifier=uuid,
                                       key_format_type=kft,
                                       key_compression_type=kct,
                                       key_wrapping_specification=kws)

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            payload_unique_identifier = None
            payload_object_type = None
            payload_secret = None
        else:
            payload_unique_identifier = payload.unique_identifier
            payload_object_type = payload.object_type
            payload_secret = payload.secret

        result = GetResult(batch_item.result_status,
                           batch_item.result_reason,
                           batch_item.result_message,
                           payload_object_type,
                           payload_unique_identifier,
                           payload_secret)
        return result

    def _activate(self, unique_identifier=None, credential=None):
        operation = Operation(OperationEnum.ACTIVATE)

        uuid = None
        if unique_identifier is not None:
            uuid = attr.UniqueIdentifier(unique_identifier)

        payload = activate.ActivateRequestPayload(unique_identifier=uuid)

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=payload)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            payload_unique_identifier = None
        else:
            payload_unique_identifier = payload.unique_identifier

        result = ActivateResult(batch_item.result_status,
                                batch_item.result_reason,
                                batch_item.result_message,
                                payload_unique_identifier)
        return result

    def _destroy(self,
                 unique_identifier=None,
                 credential=None):
        operation = Operation(OperationEnum.DESTROY)

        uuid = None
        if unique_identifier is not None:
            uuid = attr.UniqueIdentifier(unique_identifier)

        payload = destroy.DestroyRequestPayload(unique_identifier=uuid)

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=payload)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            payload_unique_identifier = None
        else:
            payload_unique_identifier = payload.unique_identifier

        result = DestroyResult(batch_item.result_status,
                               batch_item.result_reason,
                               batch_item.result_message,
                               payload_unique_identifier)
        return result

    def _revoke(self, unique_identifier=None, revocation_code=None,
                revocation_message=None, credential=None):
        operation = Operation(OperationEnum.REVOKE)

        reason = objects.RevocationReason(code=revocation_code,
                                          message=revocation_message)
        uuid = None
        if unique_identifier is not None:
            uuid = attr.UniqueIdentifier(unique_identifier)

        payload = revoke.RevokeRequestPayload(
            unique_identifier=uuid,
            revocation_reason=reason,
            compromise_date=None)  # TODO(tim-kelsey): sort out date handling

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=payload)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            payload_unique_identifier = None
        else:
            payload_unique_identifier = payload.unique_identifier

        result = RevokeResult(batch_item.result_status,
                              batch_item.result_reason,
                              batch_item.result_message,
                              payload_unique_identifier)
        return result

    def _register(self,
                  object_type=None,
                  template_attribute=None,
                  secret=None,
                  credential=None):
        operation = Operation(OperationEnum.REGISTER)

        if object_type is None:
            raise ValueError('object_type cannot be None')

        req_pl = register.RegisterRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute,
            secret=secret)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            payload_unique_identifier = None
            payload_template_attribute = None
        else:
            payload_unique_identifier = payload.unique_identifier
            payload_template_attribute = payload.template_attribute

        result = RegisterResult(batch_item.result_status,
                                batch_item.result_reason,
                                batch_item.result_message,
                                payload_unique_identifier,
                                payload_template_attribute)
        return result

    def _locate(self, maximum_items=None, storage_status_mask=None,
                object_group_member=None, attributes=[], credential=None):

        operation = Operation(OperationEnum.LOCATE)

        mxi = None
        ssmask = None
        objgrp = None

        if maximum_items is not None:
            mxi = locate.LocateRequestPayload.MaximumItems(maximum_items)
        if storage_status_mask is not None:
            m = storage_status_mask
            ssmask = locate.LocateRequestPayload.StorageStatusMask(m)
        if object_group_member is not None:
            o = object_group_member
            objgrp = locate.LocateRequestPayload.ObjectGroupMember(o)

        payload = locate.LocateRequestPayload(maximum_items=mxi,
                                              storage_status_mask=ssmask,
                                              object_group_member=objgrp,
                                              attributes=attributes)

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=payload)

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()

        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            uuids = None
        else:
            uuids = payload.unique_identifiers

        result = LocateResult(batch_item.result_status,
                              batch_item.result_reason,
                              batch_item.result_message,
                              uuids)
        return result

    def _mac(self,
             unique_identifier=None,
             cryptographic_parameters=None,
             data=None,
             credential=None):
        operation = Operation(OperationEnum.MAC)

        req_pl = mac.MACRequestPayload(
            unique_identifier=attr.UniqueIdentifier(unique_identifier),
            cryptographic_parameters=cryptographic_parameters,
            data=objects.Data(data))
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data)
        batch_items = message.batch_items
        batch_item = batch_items[0]
        payload = batch_item.response_payload

        if payload is None:
            payload_unique_identifier = None
            payload_mac_data = None
        else:
            payload_unique_identifier = payload.unique_identifier
            payload_mac_data = payload.mac_data

        result = MACResult(batch_item.result_status,
                           batch_item.result_reason,
                           batch_item.result_message,
                           payload_unique_identifier,
                           payload_mac_data)
        return result

    # TODO (peter-hamilton) Augment to handle device credentials
    def _build_credential(self):
        if (self.username is None) and (self.password is None):
            return None
        if self.username is None:
            raise ValueError('cannot build credential, username is None')
        if self.password is None:
            raise ValueError('cannot build credential, password is None')

        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': self.username,
                            'Password': self.password}
        credential = self.credential_factory.create_credential(
            credential_type,
            credential_value)
        return credential

    def _build_request_message(self, credential, batch_items):
        protocol_version = ProtocolVersion.create(1, 2)

        if credential is None:
            credential = self._build_credential()

        authentication = None
        if credential is not None:
            authentication = Authentication(credential)

        batch_count = BatchCount(len(batch_items))
        req_header = messages.RequestHeader(protocol_version=protocol_version,
                                            authentication=authentication,
                                            batch_count=batch_count)

        return messages.RequestMessage(request_header=req_header,
                                       batch_items=batch_items)

    def _send_message(self, message):
        stream = BytearrayStream()
        message.write(stream)
        self.protocol.write(stream.buffer)

    def _receive_message(self):
        return self.protocol.read()

    def _send_and_receive_message(self, request):
        self._send_message(request)
        response = messages.ResponseMessage()
        data = self._receive_message()
        response.read(data)
        return response

    def _set_variables(self, host, port, keyfile, certfile,
                       cert_reqs, ssl_version, ca_certs,
                       do_handshake_on_connect, suppress_ragged_eofs,
                       username, password, timeout):
        conf = ConfigHelper()

        # TODO: set this to a host list
        self.host_list_str = conf.get_valid_value(
            host, self.config, 'host', conf.DEFAULT_HOST)

        self.host_list = self._build_host_list(self.host_list_str)

        self.host = self.host_list[0]

        self.port = int(conf.get_valid_value(
            port, self.config, 'port', conf.DEFAULT_PORT))

        self.keyfile = conf.get_valid_value(
            keyfile, self.config, 'keyfile', None)

        self.certfile = conf.get_valid_value(
            certfile, self.config, 'certfile', None)

        self.cert_reqs = getattr(ssl, conf.get_valid_value(
            cert_reqs, self.config, 'cert_reqs', 'CERT_REQUIRED'))

        self.ssl_version = getattr(ssl, conf.get_valid_value(
            ssl_version, self.config, 'ssl_version', conf.DEFAULT_SSL_VERSION))

        self.ca_certs = conf.get_valid_value(
            ca_certs, self.config, 'ca_certs', conf.DEFAULT_CA_CERTS)

        if conf.get_valid_value(
                do_handshake_on_connect, self.config,
                'do_handshake_on_connect', 'True') == 'True':
            self.do_handshake_on_connect = True
        else:
            self.do_handshake_on_connect = False

        if conf.get_valid_value(
                suppress_ragged_eofs, self.config,
                'suppress_ragged_eofs', 'True') == 'True':
            self.suppress_ragged_eofs = True
        else:
            self.suppress_ragged_eofs = False

        self.username = conf.get_valid_value(
            username, self.config, 'username', conf.DEFAULT_USERNAME)

        self.password = conf.get_valid_value(
            password, self.config, 'password', conf.DEFAULT_PASSWORD)

        self.timeout = int(conf.get_valid_value(
            timeout, self.config, 'timeout', conf.DEFAULT_TIMEOUT))
        if self.timeout < 0:
            self.logger.warning(
                "Negative timeout value specified, "
                "resetting to safe default of {0} seconds".format(
                    conf.DEFAULT_TIMEOUT))
            self.timeout = conf.DEFAULT_TIMEOUT

    def _build_host_list(self, host_list_str):
        '''
        This internal function takes the host string from the config file
        and turns it into a list
        :return: LIST host list
        '''

        host_list = []
        if isinstance(host_list_str, str):
            host_list = host_list_str.replace(' ', '').split(',')
        else:
            raise TypeError("Unrecognized variable type provided for host "
                            "list string. 'String' type expected but '" +
                            str(type(host_list_str)) + "' received")
        return host_list
