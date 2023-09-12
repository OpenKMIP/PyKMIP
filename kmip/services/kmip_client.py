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

from __future__ import print_function

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

from kmip.core import enums
from kmip.core.enums import AuthenticationSuite
from kmip.core.enums import ConformanceClause
from kmip.core.enums import CredentialType
from kmip.core.enums import Operation as OperationEnum

from kmip.core import exceptions

from kmip.core.factories.credentials import CredentialFactory

from kmip.core import objects
from kmip.core import primitives

from kmip.core.messages.contents import Authentication
from kmip.core.messages.contents import BatchCount
from kmip.core.messages.contents import Operation
from kmip.core.messages.contents import ProtocolVersion

from kmip.core.messages import messages

from kmip.core.messages import payloads

from kmip.services.kmip_protocol import KMIPProtocol

from kmip.core.config_helper import ConfigHelper

from kmip.core.utils import BytearrayStream

import logging
import logging.config
import os
import six
import socket
import ssl
import sys

FILE_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.normpath(os.path.join(FILE_PATH, '../kmipconfig.ini'))


class KMIPProxy(object):

    def __init__(self, host=None, port=None, keyfile=None,
                 certfile=None,
                 cert_reqs=None, ssl_version=None, ca_certs=None,
                 do_handshake_on_connect=None,
                 suppress_ragged_eofs=None,
                 username=None, password=None, timeout=30, config='client',
                 config_file=None,
                 kmip_version=None):
        self.logger = logging.getLogger(__name__)
        self.credential_factory = CredentialFactory()
        self.config = config
        # Even partially-initialized objects need to be garbage collected, so
        # make sure we have a socket attr before we go raising ValueErrors.
        # Otherwise, we can hit AttributeErrors when __del__ is called.
        self.socket = None

        self._kmip_version = None
        if kmip_version:
            self.kmip_version = kmip_version
        else:
            self.kmip_version = enums.KMIPVersion.KMIP_1_2

        if config_file:
            if not isinstance(config_file, six.string_types):
                raise ValueError(
                    "The client configuration file argument must be a string."
                )
            if not os.path.exists(config_file):
                raise ValueError(
                    "The client configuration file '{}' does not "
                    "exist.".format(config_file)
                )

        self._set_variables(host, port, keyfile, certfile,
                            cert_reqs, ssl_version, ca_certs,
                            do_handshake_on_connect, suppress_ragged_eofs,
                            username, password, timeout, config_file)
        self.batch_items = []

        self.conformance_clauses = [
            ConformanceClause.DISCOVER_VERSIONS]

        self.authentication_suites = [
            AuthenticationSuite.BASIC,
            AuthenticationSuite.TLS12]

    @property
    def kmip_version(self):
        """
        Get the KMIP version for the client.

        Return:
            kmip_version (KMIPVersion): The KMIPVersion enumeration used by
                the client for KMIP requests.
        """
        return self._kmip_version

    @kmip_version.setter
    def kmip_version(self, value):
        """
        Set the KMIP version for the client.

        Args:
            value (KMIPVersion): A KMIPVersion enumeration

        Return:
            None

        Raises:
            ValueError: if value is not a KMIPVersion enumeration

        Example:
            >>> client.kmip_version = enums.KMIPVersion.KMIP_1_1
            >>>
        """
        if isinstance(value, enums.KMIPVersion):
            self._kmip_version = value
        else:
            raise ValueError("KMIP version must be a KMIPVersion enumeration")

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
                                  "appliance %s: %s", self.host, e)
                self.socket.close()
                last_error = sys.exc_info()
            else:
                return

        self.socket = None
        if last_error:
            six.reraise(*last_error)

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
        # Close the socket.
        if self.socket:
            try:
                self.socket.close()
            except (OSError, socket.error):
                # Can be thrown if the socket is not actually connected to
                # anything. In this case, ignore the error.
                pass
            self.socket = None

    def send_request_payload(self, operation, payload, credential=None):
        """
        Send a KMIP request.

        Args:
            operation (enum): An Operation enumeration specifying the type
                of operation to be requested. Required.
            payload (struct): A RequestPayload structure containing the
                parameters for a specific KMIP operation. Required.
            credential (struct): A Credential structure containing
                authentication information for the server. Optional, defaults
                to None.

        Returns:
            response (struct): A ResponsePayload structure containing the
                results of the KMIP operation specified in the request.

        Raises:
            TypeError: if the payload is not a RequestPayload instance or if
                the operation and payload type do not match
            InvalidMessage: if the response message does not have the right
                number of response payloads, or does not match the request
                operation
        """
        if not isinstance(payload, payloads.RequestPayload):
            raise TypeError(
                "The request payload must be a RequestPayload object."
            )

        # TODO (peterhamilton) For now limit this to the new Delete/Set/Modify
        # Attribute operations. Migrate over existing operations to use
        # this method instead.
        if operation == enums.Operation.DELETE_ATTRIBUTE:
            if not isinstance(payload, payloads.DeleteAttributeRequestPayload):
                raise TypeError(
                    "The request payload for the DeleteAttribute operation "
                    "must be a DeleteAttributeRequestPayload object."
                )
        elif operation == enums.Operation.SET_ATTRIBUTE:
            if not isinstance(payload, payloads.SetAttributeRequestPayload):
                raise TypeError(
                    "The request payload for the SetAttribute operation must "
                    "be a SetAttributeRequestPayload object."
                )
        elif operation == enums.Operation.MODIFY_ATTRIBUTE:
            if not isinstance(payload, payloads.ModifyAttributeRequestPayload):
                raise TypeError(
                    "The request payload for the ModifyAttribute operation "
                    "must be a ModifyAttributeRequestPayload object."
                )

        batch_item = messages.RequestBatchItem(
            operation=primitives.Enumeration(
                enums.Operation,
                operation,
                tag=enums.Tags.OPERATION
            ),
            request_payload=payload
        )

        request_message = self._build_request_message(credential, [batch_item])
        response_message = self._send_and_receive_message(request_message)

        if len(response_message.batch_items) != 1:
            raise exceptions.InvalidMessage(
                "The response message does not have the right number of "
                "requested operation results."
            )

        batch_item = response_message.batch_items[0]

        if batch_item.result_status.value != enums.ResultStatus.SUCCESS:
            raise exceptions.OperationFailure(
                batch_item.result_status.value,
                batch_item.result_reason.value,
                batch_item.result_message.value
            )

        if batch_item.operation.value != operation:
            raise exceptions.InvalidMessage(
                "The response message does not match the request operation."
            )

        # TODO (peterhamilton) Same as above for now.
        if batch_item.operation.value == enums.Operation.DELETE_ATTRIBUTE:
            if not isinstance(
                batch_item.response_payload,
                payloads.DeleteAttributeResponsePayload
            ):
                raise exceptions.InvalidMessage(
                    "Invalid response payload received for the "
                    "DeleteAttribute operation."
                )
        elif batch_item.operation.value == enums.Operation.SET_ATTRIBUTE:
            if not isinstance(
                batch_item.response_payload,
                payloads.SetAttributeResponsePayload
            ):
                raise exceptions.InvalidMessage(
                    "Invalid response payload received for the SetAttribute "
                    "operation."
                )
        elif batch_item.operation.value == enums.Operation.MODIFY_ATTRIBUTE:
            if not isinstance(
                batch_item.response_payload,
                payloads.ModifyAttributeResponsePayload
            ):
                raise exceptions.InvalidMessage(
                    "Invalid response payload received for the "
                    "ModifyAttribute operation."
                )

        return batch_item.response_payload

    def create(self, object_type, template_attribute, credential=None):
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

    def rekey(self,
              uuid=None,
              offset=None,
              template_attribute=None,
              credential=None):
        """
        Check object usage according to specific constraints.

        Args:
            uuid (string): The unique identifier of a managed cryptographic
                object that should be checked. Optional, defaults to None.
            offset (int): An integer specifying, in seconds, the difference
                between the rekeyed objects initialization date and activation
                date. Optional, defaults to None.
            template_attribute (TemplateAttribute): A TemplateAttribute struct
                containing the attributes to set on the newly rekeyed object.
                Optional, defaults to None.
            credential (Credential): A Credential struct containing a set of
                authorization parameters for the operation. Optional, defaults
                to None.

        Returns:
            dict: The results of the check operation, containing the following
                key/value pairs:

                Key                        | Value
                ---------------------------|-----------------------------------
                'unique_identifier'        | (string) The unique ID of the
                                           | checked cryptographic object.
                'template_attribute'       | (TemplateAttribute) A struct
                                           | containing attribute set by the
                                           | server. Optional.
                'result_status'            | (ResultStatus) An enumeration
                                           | indicating the status of the
                                           | operation result.
                'result_reason'            | (ResultReason) An enumeration
                                           | providing context for the result
                                           | status.
                'result_message'           | (string) A message providing
                                           | additional context for the
                                           | operation result.
        """
        operation = Operation(OperationEnum.REKEY)
        request_payload = payloads.RekeyRequestPayload(
            unique_identifier=uuid,
            offset=offset,
            template_attribute=template_attribute
        )
        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=request_payload
        )

        request = self._build_request_message(credential, [batch_item])
        response = self._send_and_receive_message(request)
        batch_item = response.batch_items[0]
        payload = batch_item.response_payload

        result = {}

        if payload:
            result['unique_identifier'] = payload.unique_identifier

            if payload.template_attribute is not None:
                result['template_attribute'] = payload.template_attribute

        result['result_status'] = batch_item.result_status.value
        try:
            result['result_reason'] = batch_item.result_reason.value
        except Exception:
            result['result_reason'] = batch_item.result_reason
        try:
            result['result_message'] = batch_item.result_message.value
        except Exception:
            result['result_message'] = batch_item.result_message

        return result

    def derive_key(self,
                   object_type,
                   unique_identifiers,
                   derivation_method,
                   derivation_parameters,
                   template_attribute,
                   credential=None):
        """
        Derive a new key or secret data from an existing managed object.

        Args:
            object_type (ObjectType): An ObjectType enumeration specifying
                what type of object to create. Required.
            unique_identifiers (list): A list of strings specifying the unique
                IDs of the existing managed objects to use for key derivation.
                Required.
            derivation_method (DerivationMethod): A DerivationMethod
                enumeration specifying what key derivation method to use.
                Required.
            derivation_parameters (DerivationParameters): A
                DerivationParameters struct containing the settings and
                options to use for key derivation.
            template_attribute (TemplateAttribute): A TemplateAttribute struct
                containing the attributes to set on the newly derived object.
            credential (Credential): A Credential struct containing a set of
                authorization parameters for the operation. Optional, defaults
                to None.

        Returns:
            dict: The results of the derivation operation, containing the
                following key/value pairs:

                Key                  | Value
                ---------------------|-----------------------------------------
                'unique_identifier'  | (string) The unique ID of the newly
                                     | derived object.
                'template_attribute' | (TemplateAttribute) A struct containing
                                     | any attributes set on the newly derived
                                     | object.
                'result_status'      | (ResultStatus) An enumeration indicating
                                     | the status of the operation result.
                'result_reason'      | (ResultReason) An enumeration providing
                                     | context for the result status.
                'result_message'     | (string) A message providing additional
                                     | context for the operation result.
        """
        operation = Operation(OperationEnum.DERIVE_KEY)
        request_payload = payloads.DeriveKeyRequestPayload(
            object_type=object_type,
            unique_identifiers=unique_identifiers,
            derivation_method=derivation_method,
            derivation_parameters=derivation_parameters,
            template_attribute=template_attribute
        )
        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=request_payload
        )

        request = self._build_request_message(credential, [batch_item])
        response = self._send_and_receive_message(request)
        batch_item = response.batch_items[0]
        payload = batch_item.response_payload

        result = {}

        if payload:
            result['unique_identifier'] = payload.unique_identifier
            result['template_attribute'] = payload.template_attribute

        result['result_status'] = batch_item.result_status.value
        try:
            result['result_reason'] = batch_item.result_reason.value
        except Exception:
            result['result_reason'] = batch_item.result_reason
        try:
            result['result_message'] = batch_item.result_message.value
        except Exception:
            result['result_message'] = batch_item.result_message

        return result

    def check(self,
              uuid=None,
              usage_limits_count=None,
              cryptographic_usage_mask=None,
              lease_time=None,
              credential=None):
        """
        Check object usage according to specific constraints.

        Args:
            uuid (string): The unique identifier of a managed cryptographic
                object that should be checked. Optional, defaults to None.
            usage_limits_count (int): An integer specifying the number of
                items that can be secured with the specified cryptographic
                object. Optional, defaults to None.
            cryptographic_usage_mask (list): A list of CryptographicUsageMask
                enumerations specifying the operations possible with the
                specified cryptographic object. Optional, defaults to None.
            lease_time (int): The number of seconds that can be leased for the
                specified cryptographic object. Optional, defaults to None.
            credential (Credential): A Credential struct containing a set of
                authorization parameters for the operation. Optional, defaults
                to None.

        Returns:
            dict: The results of the check operation, containing the following
                key/value pairs:

                Key                        | Value
                ---------------------------|-----------------------------------
                'unique_identifier'        | (string) The unique ID of the
                                           | checked cryptographic object.
                'usage_limits_count'       | (int) The value provided as input
                                           | if the value exceeds server
                                           | constraints.
                'cryptographic_usage_mask' | (list) The value provided as input
                                           | if the value exceeds server
                                           | constraints.
                'lease_time'               | (int) The value provided as input
                                           | if the value exceeds server
                                           | constraints.
                'result_status'            | (ResultStatus) An enumeration
                                           | indicating the status of the
                                           | operation result.
                'result_reason'            | (ResultReason) An enumeration
                                           | providing context for the result
                                           | status.
                'result_message'           | (string) A message providing
                                           | additional context for the
                                           | operation result.
        """
        # TODO (peter-hamilton) Push this into the Check request.
        mask = 0
        for m in cryptographic_usage_mask:
            mask |= m.value

        operation = Operation(OperationEnum.CHECK)
        request_payload = payloads.CheckRequestPayload(
            unique_identifier=uuid,
            usage_limits_count=usage_limits_count,
            cryptographic_usage_mask=mask,
            lease_time=lease_time
        )
        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=request_payload
        )

        request = self._build_request_message(credential, [batch_item])
        response = self._send_and_receive_message(request)
        batch_item = response.batch_items[0]
        payload = batch_item.response_payload

        result = {}

        if payload:
            result['unique_identifier'] = payload.unique_identifier
        if payload.usage_limits_count is not None:
            result['usage_limits_count'] = payload.usage_limits_count
        if payload.cryptographic_usage_mask is not None:
            # TODO (peter-hamilton) Push this into the Check response.
            masks = []
            for enumeration in enums.CryptographicUsageMask:
                if payload.cryptographic_usage_mask & enumeration.value:
                    masks.append(enumeration)
            result['cryptographic_usage_mask'] = masks
        if payload.lease_time is not None:
            result['lease_time'] = payload.lease_time

        result['result_status'] = batch_item.result_status.value
        try:
            result['result_reason'] = batch_item.result_reason.value
        except Exception:
            result['result_reason'] = batch_item.result_reason
        try:
            result['result_message'] = batch_item.result_message.value
        except Exception:
            result['result_message'] = batch_item.result_message

        return result

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

    def revoke(self, revocation_reason, uuid=None, revocation_message=None,
               compromise_occurrence_date=None, credential=None):
        return self._revoke(
            unique_identifier=uuid,
            revocation_reason=revocation_reason,
            revocation_message=revocation_message,
            compromise_occurrence_date=compromise_occurrence_date,
            credential=credential)

    def destroy(self, uuid=None, credential=None):
        return self._destroy(unique_identifier=uuid,
                             credential=credential)

    def register(self, object_type, template_attribute, secret,
                 credential=None):
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
               object_group_member=None, attributes=None, credential=None,
               offset_items=None):
        return self._locate(maximum_items=maximum_items,
                            storage_status_mask=storage_status_mask,
                            object_group_member=object_group_member,
                            attributes=attributes, credential=credential,
                            offset_items=offset_items)

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

    def encrypt(self,
                data,
                unique_identifier=None,
                cryptographic_parameters=None,
                iv_counter_nonce=None,
                credential=None):
        """
        Encrypt data using the specified encryption key and parameters.

        Args:
            data (bytes): The bytes to encrypt. Required.
            unique_identifier (string): The unique ID of the encryption key
                to use. Optional, defaults to None.
            cryptographic_parameters (CryptographicParameters): A structure
                containing various cryptographic settings to be used for the
                encryption. Optional, defaults to None.
            iv_counter_nonce (bytes): The bytes to use for the IV/counter/
                nonce, if needed by the encryption algorithm and/or cipher
                mode. Optional, defaults to None.
            credential (Credential): A credential object containing a set of
                authorization parameters for the operation. Optional, defaults
                to None.

        Returns:
            dict: The results of the encrypt operation, containing the
                following key/value pairs:

                Key                 | Value
                --------------------|-----------------------------------------
                'unique_identifier' | (string) The unique ID of the encryption
                                    | key used to encrypt the data.
                'data'              | (bytes) The encrypted data.
                'iv_counter_nonce'  | (bytes) The IV/counter/nonce used for
                                    | the encryption, if autogenerated.
                'result_status'     | (ResultStatus) An enumeration indicating
                                    | the status of the operation result.
                'result_reason'     | (ResultReason) An enumeration providing
                                    | context for the result status.
                'result_message'    | (string) A message providing additional
                                    | context for the operation result.
        """
        operation = Operation(OperationEnum.ENCRYPT)

        request_payload = payloads.EncryptRequestPayload(
            unique_identifier=unique_identifier,
            data=data,
            cryptographic_parameters=cryptographic_parameters,
            iv_counter_nonce=iv_counter_nonce
        )
        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=request_payload
        )

        request = self._build_request_message(credential, [batch_item])
        response = self._send_and_receive_message(request)
        batch_item = response.batch_items[0]
        payload = batch_item.response_payload

        result = {}

        if payload:
            result['unique_identifier'] = payload.unique_identifier
            result['data'] = payload.data
            result['iv_counter_nonce'] = payload.iv_counter_nonce

        result['result_status'] = batch_item.result_status.value
        try:
            result['result_reason'] = batch_item.result_reason.value
        except Exception:
            result['result_reason'] = batch_item.result_reason
        try:
            result['result_message'] = batch_item.result_message.value
        except Exception:
            result['result_message'] = batch_item.result_message

        return result

    def decrypt(self,
                data,
                unique_identifier=None,
                cryptographic_parameters=None,
                iv_counter_nonce=None,
                credential=None):
        """
        Decrypt data using the specified decryption key and parameters.

        Args:
            data (bytes): The bytes to decrypt. Required.
            unique_identifier (string): The unique ID of the decryption key
                to use. Optional, defaults to None.
            cryptographic_parameters (CryptographicParameters): A structure
                containing various cryptographic settings to be used for the
                decryption. Optional, defaults to None.
            iv_counter_nonce (bytes): The bytes to use for the IV/counter/
                nonce, if needed by the decryption algorithm and/or cipher
                mode. Optional, defaults to None.
            credential (Credential): A credential object containing a set of
                authorization parameters for the operation. Optional, defaults
                to None.

        Returns:
            dict: The results of the decrypt operation, containing the
                following key/value pairs:

                Key                 | Value
                --------------------|-----------------------------------------
                'unique_identifier' | (string) The unique ID of the decryption
                                    | key used to decrypt the data.
                'data'              | (bytes) The decrypted data.
                'result_status'     | (ResultStatus) An enumeration indicating
                                    | the status of the operation result.
                'result_reason'     | (ResultReason) An enumeration providing
                                    | context for the result status.
                'result_message'    | (string) A message providing additional
                                    | context for the operation result.
        """
        operation = Operation(OperationEnum.DECRYPT)

        request_payload = payloads.DecryptRequestPayload(
            unique_identifier=unique_identifier,
            data=data,
            cryptographic_parameters=cryptographic_parameters,
            iv_counter_nonce=iv_counter_nonce
        )
        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=request_payload
        )

        request = self._build_request_message(credential, [batch_item])
        response = self._send_and_receive_message(request)
        batch_item = response.batch_items[0]
        payload = batch_item.response_payload

        result = {}

        if payload:
            result['unique_identifier'] = payload.unique_identifier
            result['data'] = payload.data

        result['result_status'] = batch_item.result_status.value
        try:
            result['result_reason'] = batch_item.result_reason.value
        except Exception:
            result['result_reason'] = batch_item.result_reason
        try:
            result['result_message'] = batch_item.result_message.value
        except Exception:
            result['result_message'] = batch_item.result_message

        return result

    def signature_verify(self,
                         message,
                         signature,
                         unique_identifier=None,
                         cryptographic_parameters=None,
                         credential=None):
        """
        Verify a message signature using the specified signing key.

        Args:
            message (bytes): The bytes of the signed message. Required.
            signature (bytes): The bytes of the message signature. Required.
            unique_identifier (string): The unique ID of the signing key to
                use. Optional, defaults to None.
            cryptographic_parameters (CryptographicParameters): A structure
                containing various cryptographic settings to be used for
                signature verification. Optional, defaults to None.
            credential (Credential): A credential object containing a set of
                authorization parameters for the operation. Optional, defaults
                to None.

        Returns:
            dict: The results of the signature verify operation, containing the
                following key/value pairs:

                Key                  | Value
                ---------------------|-----------------------------------------
                'unique_identifier'  | (string) The unique ID of the signing
                                     | key used to verify the signature.
                'validity_indicator' | (ValidityIndicator) An enumeration
                                     | indicating the result of signature
                                     | verification.
                'result_status'      | (ResultStatus) An enumeration indicating
                                     | the status of the operation result.
                'result_reason'      | (ResultReason) An enumeration providing
                                     | context for the result status.
                'result_message'     | (string) A message providing additional
                                     | context for the operation result.
        """
        operation = Operation(OperationEnum.SIGNATURE_VERIFY)

        request_payload = payloads.SignatureVerifyRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=cryptographic_parameters,
            data=message,
            signature_data=signature
        )
        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=request_payload
        )

        request = self._build_request_message(credential, [batch_item])
        response = self._send_and_receive_message(request)
        batch_item = response.batch_items[0]
        payload = batch_item.response_payload

        result = {}

        if payload:
            result['unique_identifier'] = payload.unique_identifier
            result['validity_indicator'] = payload.validity_indicator

        result['result_status'] = batch_item.result_status.value
        try:
            result['result_reason'] = batch_item.result_reason.value
        except Exception:
            result['result_reason'] = batch_item.result_reason
        try:
            result['result_message'] = batch_item.result_message.value
        except Exception:
            result['result_message'] = batch_item.result_message

        return result

    def sign(self, data, unique_identifier=None,
             cryptographic_parameters=None, credential=None):
        """
        Sign specified data using a specified signing key.

        Args:
            data (bytes): Data to be signed. Required.
            unique_identifier (string): The unique ID of the signing
                key to be used. Optional, defaults to None.
            cryptographic_parameters (CryptographicParameters): A structure
                containing various cryptographic settings to be used for
                creating the signature. Optional, defaults to None.
            credential (Credential): A credential object containing a set of
                authorization parameters for the operation. Optional, defaults
                to None.
        Returns:
            dict: The results of the sign operation, containing the
                following key/value pairs:

            Key                  | Value
            ---------------------|-----------------------------------------
            'unique_identifier'  | (string) The unique ID of the signing
                                 | key used to create the signature
            'signature'          | (bytes) The bytes of the signature
            'result_status'      | (ResultStatus) An enumeration indicating
                                 | the status of the operation result
            'result_reason'      | (ResultReason) An enumeration providing
                                 | context for the result status.
            'result_message'     | (string) A message providing additional
                                 | context for the operation result.
        """
        operation = Operation(OperationEnum.SIGN)

        request_payload = payloads.SignRequestPayload(
            unique_identifier=unique_identifier,
            cryptographic_parameters=cryptographic_parameters,
            data=data
        )

        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=request_payload
        )

        request = self._build_request_message(credential, [batch_item])
        response = self._send_and_receive_message(request)
        batch_item = response.batch_items[0]
        payload = batch_item.response_payload

        result = {}

        if payload:
            result['unique_identifier'] = payload.unique_identifier
            result['signature'] = payload.signature_data
        result['result_status'] = batch_item.result_status.value
        try:
            result['result_reason'] = batch_item.result_reason.value
        except Exception:
            result['result_reason'] = batch_item.result_reason
        try:
            result['result_message'] = batch_item.result_message.value
        except Exception:
            result['result_message'] = batch_item.result_message

        return result

    def mac(self, data, unique_identifier=None,
            cryptographic_parameters=None, credential=None):
        return self._mac(
            data=data,
            unique_identifier=unique_identifier,
            cryptographic_parameters=cryptographic_parameters,
            credential=credential)

    def _create(self,
                object_type=None,
                template_attribute=None,
                credential=None):
        operation = Operation(OperationEnum.CREATE)

        if object_type is None:
            raise ValueError('object_type cannot be None')

        req_pl = payloads.CreateRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data, self.kmip_version)
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
        payload = payloads.CreateKeyPairRequestPayload(
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
        payload = payloads.RekeyKeyPairRequestPayload(
            private_key_uuid, offset,
            common_template_attribute=common_template_attribute,
            private_key_template_attribute=private_key_template_attribute,
            public_key_template_attribute=public_key_template_attribute)
        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _build_query_batch_item(self, query_functions=None):
        operation = Operation(OperationEnum.QUERY)
        payload = payloads.QueryRequestPayload(query_functions)
        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _build_get_attributes_batch_item(
            self,
            uuid=None,
            attribute_names=None
    ):
        operation = Operation(OperationEnum.GET_ATTRIBUTES)
        payload = payloads.GetAttributesRequestPayload(
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
        payload = payloads.GetAttributeListRequestPayload(uid)
        batch_item = messages.RequestBatchItem(
            operation=operation, request_payload=payload)
        return batch_item

    def _build_discover_versions_batch_item(self, protocol_versions=None):
        operation = Operation(OperationEnum.DISCOVER_VERSIONS)

        payload = payloads.DiscoverVersionsRequestPayload(
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
            uid = payload.unique_identifier
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
            payload_private_key_uuid = payload.private_key_unique_identifier
            payload_public_key_uuid = payload.public_key_unique_identifier
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

        if key_format_type is not None:
            key_format_type = key_format_type.value

        req_pl = payloads.GetRequestPayload(
            unique_identifier=unique_identifier,
            key_format_type=key_format_type,
            key_compression_type=key_compression_type,
            key_wrapping_specification=key_wrapping_specification
        )

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data, self.kmip_version)
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

        payload = payloads.ActivateRequestPayload(unique_identifier=uuid)

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=payload)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data, self.kmip_version)
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

        payload = payloads.DestroyRequestPayload(unique_identifier=uuid)

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=payload)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data, self.kmip_version)
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

    def _revoke(self, unique_identifier=None, revocation_reason=None,
                revocation_message=None, compromise_occurrence_date=None,
                credential=None):
        operation = Operation(OperationEnum.REVOKE)

        reason = objects.RevocationReason(code=revocation_reason,
                                          message=revocation_message)
        uuid = None
        if unique_identifier is not None:
            uuid = attr.UniqueIdentifier(unique_identifier)

        payload = payloads.RevokeRequestPayload(
            unique_identifier=uuid,
            revocation_reason=reason,
            compromise_occurrence_date=compromise_occurrence_date)

        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=payload)
        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data, self.kmip_version)
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

        req_pl = payloads.RegisterRequestPayload(
            object_type=object_type,
            template_attribute=template_attribute,
            managed_object=secret)
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data, self.kmip_version)
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
                object_group_member=None, attributes=None, credential=None,
                offset_items=None):

        operation = Operation(OperationEnum.LOCATE)

        payload = payloads.LocateRequestPayload(
            maximum_items=maximum_items,
            offset_items=offset_items,
            storage_status_mask=storage_status_mask,
            object_group_member=object_group_member,
            attributes=attributes
        )

        batch_item = messages.RequestBatchItem(
            operation=operation,
            request_payload=payload
        )

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()

        message.read(data, self.kmip_version)
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
             data,
             unique_identifier=None,
             cryptographic_parameters=None,
             credential=None):
        operation = Operation(OperationEnum.MAC)

        req_pl = payloads.MACRequestPayload(
            unique_identifier=attr.UniqueIdentifier(unique_identifier),
            cryptographic_parameters=cryptographic_parameters,
            data=objects.Data(data))
        batch_item = messages.RequestBatchItem(operation=operation,
                                               request_payload=req_pl)

        message = self._build_request_message(credential, [batch_item])
        self._send_message(message)
        message = messages.ResponseMessage()
        data = self._receive_message()
        message.read(data, self.kmip_version)
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

    def _build_protocol_version(self):
        if self.kmip_version == enums.KMIPVersion.KMIP_1_0:
            return ProtocolVersion(1, 0)
        elif self.kmip_version == enums.KMIPVersion.KMIP_1_1:
            return ProtocolVersion(1, 1)
        elif self.kmip_version == enums.KMIPVersion.KMIP_1_2:
            return ProtocolVersion(1, 2)
        elif self.kmip_version == enums.KMIPVersion.KMIP_1_3:
            return ProtocolVersion(1, 3)
        elif self.kmip_version == enums.KMIPVersion.KMIP_1_4:
            return ProtocolVersion(1, 4)
        else:
            return ProtocolVersion(2, 0)

    def _build_request_message(self, credential, batch_items):
        protocol_version = self._build_protocol_version()

        if credential is None:
            credential = self._build_credential()

        authentication = None
        if credential is not None:
            authentication = Authentication([credential])

        batch_count = BatchCount(len(batch_items))
        req_header = messages.RequestHeader(protocol_version=protocol_version,
                                            authentication=authentication,
                                            batch_count=batch_count)

        return messages.RequestMessage(request_header=req_header,
                                       batch_items=batch_items)

    def _send_message(self, message):
        stream = BytearrayStream()
        message.write(stream, self.kmip_version)
        self.protocol.write(stream.buffer)

    def _receive_message(self):
        return self.protocol.read()

    def _send_and_receive_message(self, request):
        self._send_message(request)
        response = messages.ResponseMessage()
        data = self._receive_message()
        response.read(data, self.kmip_version)
        return response

    def _set_variables(self, host, port, keyfile, certfile,
                       cert_reqs, ssl_version, ca_certs,
                       do_handshake_on_connect, suppress_ragged_eofs,
                       username, password, timeout, config_file):
        conf = ConfigHelper(config_file)

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
