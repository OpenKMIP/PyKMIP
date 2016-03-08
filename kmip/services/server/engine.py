# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

import logging
import sqlalchemy

from sqlalchemy.orm import exc

import threading
import time

import kmip

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions

from kmip.core.messages import contents
from kmip.core.messages import messages

from kmip.core.messages.payloads import destroy
from kmip.core.messages.payloads import discover_versions
from kmip.core.messages.payloads import query

from kmip.core import misc

from kmip.pie import sqltypes
from kmip.pie import objects

from kmip.services.server.crypto import engine


class KmipEngine(object):
    """
    A KMIP request processor that acts as the core of the KmipServer.

    The KmipEngine contains the core application logic for the KmipServer.
    It processes all KMIP requests and maintains consistent state across
    client connections.

    Features that are not supported:
        * KMIP versions > 1.1
        * Numerous operations, objects, and attributes.
        * User authentication
        * Batch processing options: UNDO
        * Asynchronous operations
        * Operation policies
        * Object archival
    """

    def __init__(self):
        """
        Create a KmipEngine.
        """
        self._logger = logging.getLogger(__name__)

        self._cryptography_engine = engine.CryptographyEngine()

        self._data_store = sqlalchemy.create_engine(
            'sqlite:///:memory:',
            echo=False
        )
        sqltypes.Base.metadata.create_all(self._data_store)
        self._data_store_session_factory = sqlalchemy.orm.sessionmaker(
            bind=self._data_store
        )

        self._lock = threading.RLock()

        self._id_placeholder = None

        self._protocol_versions = [
            contents.ProtocolVersion.create(1, 2),
            contents.ProtocolVersion.create(1, 1),
            contents.ProtocolVersion.create(1, 0)
        ]

        self._protocol_version = self._protocol_versions[0]

        self._object_map = {
            enums.ObjectType.CERTIFICATE: objects.X509Certificate,
            enums.ObjectType.SYMMETRIC_KEY: objects.SymmetricKey,
            enums.ObjectType.PUBLIC_KEY: objects.PublicKey,
            enums.ObjectType.PRIVATE_KEY: objects.PrivateKey,
            enums.ObjectType.SPLIT_KEY: None,
            enums.ObjectType.TEMPLATE: None,
            enums.ObjectType.SECRET_DATA: objects.SecretData,
            enums.ObjectType.OPAQUE_DATA: objects.OpaqueObject
        }

    def _kmip_version_supported(supported):
        def decorator(function):
            def wrapper(self, *args, **kwargs):
                if float(str(self._protocol_version)) < float(supported):
                    name = function.__name__
                    operation = ''.join(
                        [x.capitalize() for x in name[9:].split('_')]
                    )
                    raise exceptions.OperationNotSupported(
                        "{0} is not supported by KMIP {1}".format(
                            operation,
                            self._protocol_version
                        )
                    )
                else:
                    return function(self, *args, **kwargs)
            return wrapper
        return decorator

    def _synchronize(function):
        def decorator(self, *args, **kwargs):
            with self._lock:
                return function(self, *args, **kwargs)
        return decorator

    def _set_protocol_version(self, protocol_version):
        if protocol_version in self._protocol_versions:
            self._protocol_version = protocol_version
        else:
            raise exceptions.InvalidMessage(
                "KMIP {0} is not supported by the server.".format(
                    protocol_version
                )
            )

    def _verify_credential(self, request_credential, connection_credential):
        # TODO (peterhamilton) Add authentication support
        # 1. If present, verify user ID of connection_credential is valid user.
        # 2. If present, verify request_credential is valid credential.
        # 3. If both present, verify that they are compliant with each other.
        # 4. If neither present, set server to only allow Query operations.
        pass

    @_synchronize
    def process_request(self, request, credential=None):
        """
        Process a KMIP request message.

        This routine is the main driver of the KmipEngine. It breaks apart and
        processes the request header, handles any message errors that may
        result, and then passes the set of request batch items on for
        processing. This routine is thread-safe, allowing multiple client
        connections to use the same KmipEngine.

        Args:
            request (RequestMessage): The request message containing the batch
                items to be processed.
            credential (Credential): A credential containing any identifying
                information about the client obtained from the client
                certificate. Optional, defaults to None.

        Returns:
            ResponseMessage: The response containing all of the results from
                the request batch items.
        """
        header = request.request_header

        # Process the protocol version
        self._set_protocol_version(header.protocol_version)

        # Process the maximum response size
        max_response_size = None
        if header.maximum_response_size:
            max_response_size = header.maximum_response_size.value

        # Process the time stamp
        now = int(time.time())
        if header.time_stamp:
            then = header.time_stamp.value

            if (now >= then) and ((now - then) < 60):
                self._logger.info("Received request at time: {0}".format(
                    time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.gmtime(then)
                    )
                ))
            else:
                if now < then:
                    self._logger.warning(
                        "Received request with future timestamp. Received "
                        "timestamp: {0}, Current timestamp: {1}".format(
                            then,
                            now
                        )
                    )

                    raise exceptions.InvalidMessage(
                        "Future request rejected by server."
                    )
                else:
                    self._logger.warning(
                        "Received request with old timestamp. Possible "
                        "replay attack. Received timestamp: {0}, Current "
                        "timestamp: {1}".format(then, now)
                    )

                    raise exceptions.InvalidMessage(
                        "Stale request rejected by server."
                    )
        else:
            self._logger.info("Received request at time: {0}".format(
                time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.gmtime(now)
                )
            ))

        # Process the asynchronous indicator
        self.is_asynchronous = False
        if header.asynchronous_indicator is not None:
            self.is_asynchronous = header.asynchronous_indicator.value

        if self.is_asynchronous:
            raise exceptions.InvalidMessage(
                "Asynchronous operations are not supported."
            )

        # Process the authentication credentials
        auth_credentials = header.authentication.credential
        self._verify_credential(auth_credentials, credential)

        # Process the batch error continuation option
        batch_error_option = enums.BatchErrorContinuationOption.STOP
        if header.batch_error_cont_option is not None:
            batch_error_option = header.batch_error_cont_option.value

        if batch_error_option == enums.BatchErrorContinuationOption.UNDO:
            raise exceptions.InvalidMessage(
                "Undo option for batch handling is not supported."
            )

        # Process the batch order option
        batch_order_option = False
        if header.batch_order_option:
            batch_order_option = header.batch_order_option.value

        response_batch = self._process_batch(
            request.batch_items,
            batch_error_option,
            batch_order_option
        )
        response = self._build_response(
            header.protocol_version,
            response_batch
        )

        return response, max_response_size

    def _build_response(self, version, batch_items):
        header = messages.ResponseHeader(
            protocol_version=version,
            time_stamp=contents.TimeStamp(int(time.time())),
            batch_count=contents.BatchCount(len(batch_items))
        )
        message = messages.ResponseMessage(
            response_header=header,
            batch_items=batch_items
        )
        return message

    def build_error_response(self, version, reason, message):
        """
        Build a simple ResponseMessage with a single error result.

        Args:
            version (ProtocolVersion): The protocol version the response
                should be addressed with.
            reason (ResultReason): An enumeration classifying the type of
                error occurred.
            message (str): A string providing additional information about
                the error.

        Returns:
            ResponseMessage: The simple ResponseMessage containing a
                single error result.
        """
        batch_item = messages.ResponseBatchItem(
            result_status=contents.ResultStatus(
                enums.ResultStatus.OPERATION_FAILED
            ),
            result_reason=contents.ResultReason(reason),
            result_message=contents.ResultMessage(message)
        )
        return self._build_response(version, [batch_item])

    def _process_batch(self, request_batch, batch_handling, batch_order):
        response_batch = list()

        self._data_session = self._data_store_session_factory()

        for batch_item in request_batch:
            error_occurred = False

            response_payload = None
            result_status = None
            result_reason = None
            result_message = None

            operation = batch_item.operation
            request_payload = batch_item.request_payload

            # Process batch item ID.
            if len(request_batch) > 1:
                if not batch_item.unique_batch_item_id:
                    raise exceptions.InvalidMessage(
                        "Batch item ID is undefined."
                    )

            # Process batch message extension.
            # TODO (peterhamilton) Add support for message extension handling.
            # 1. Extract the vendor identification and criticality indicator.
            # 2. If the indicator is True, raise an error.
            # 3. If the indicator is False, ignore the extension.

            # Process batch payload.
            try:
                response_payload = self._process_operation(
                    operation.value,
                    request_payload
                )

                result_status = enums.ResultStatus.SUCCESS
            except exceptions.KmipError as e:
                error_occurred = True
                result_status = e.status
                result_reason = e.reason
                result_message = str(e)
            except Exception as e:
                self._logger.warning(
                    "Error occurred while processing operation."
                )
                self._logger.exception(e)

                error_occurred = True
                result_status = enums.ResultStatus.OPERATION_FAILED
                result_reason = enums.ResultReason.GENERAL_FAILURE
                result_message = (
                    "Operation failed. See the server logs for more "
                    "information."
                )

            # Compose operation result.
            result_status = contents.ResultStatus(result_status)
            if result_reason:
                result_reason = contents.ResultReason(result_reason)
            if result_message:
                result_message = contents.ResultMessage(result_message)

            batch_item = messages.ResponseBatchItem(
                operation=batch_item.operation,
                unique_batch_item_id=batch_item.unique_batch_item_id,
                result_status=result_status,
                result_reason=result_reason,
                result_message=result_message,
                response_payload=response_payload
            )
            response_batch.append(batch_item)

            # Handle batch error if necessary.
            if error_occurred:
                if batch_handling == enums.BatchErrorContinuationOption.STOP:
                    break

        return response_batch

    def _process_operation(self, operation, payload):
        if operation == enums.Operation.DESTROY:
            return self._process_destroy(payload)
        if operation == enums.Operation.QUERY:
            return self._process_query(payload)
        elif operation == enums.Operation.DISCOVER_VERSIONS:
            return self._process_discover_versions(payload)
        else:
            raise exceptions.OperationNotSupported(
                "{0} operation is not supported by the server.".format(
                    operation.name.title()
                )
            )

    @_kmip_version_supported('1.0')
    def _process_destroy(self, payload):
        self._logger.info("Processing operation: Destroy")

        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier.value
        else:
            unique_identifier = self._id_placeholder

        try:
            object_type = self._data_session.query(
                objects.ManagedObject._object_type
            ).filter(
                objects.ManagedObject.unique_identifier == unique_identifier
            ).one()[0]
        except exc.NoResultFound as e:
            self._logger.warning(
                "Could not identify object type for object: {0}".format(
                    unique_identifier
                )
            )
            self._logger.exception(e)
            raise exceptions.ItemNotFound(
                "Could not locate object: {0}".format(unique_identifier)
            )
        except exc.MultipleResultsFound as e:
            self._logger.warning(
                "Multiple objects found for ID: {0}".format(
                    unique_identifier
                )
            )
            raise e

        table = self._object_map.get(object_type)
        if table is None:
            name = object_type.name
            raise exceptions.InvalidField(
                "The {0} object type is not supported.".format(
                    ''.join(
                        [x.capitalize() for x in name[9:].split('_')]
                    )
                )
            )

        # TODO (peterhamilton) Process attributes to see if destroy possible
        # 1. Check object state. If invalid, error out.
        # 2. Check object deactivation date. If invalid, error out.

        self._data_session.query(table).filter(
            table.unique_identifier == unique_identifier
        ).delete()

        response_payload = destroy.DestroyResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(unique_identifier)
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_query(self, payload):
        self._logger.info("Processing operation: Query")

        queries = [x.value for x in payload.query_functions]

        operations = list()
        objects = list()
        vendor_identification = None
        server_information = None
        namespaces = list()
        extensions = list()

        if enums.QueryFunction.QUERY_OPERATIONS in queries:
            operations = list([
                contents.Operation(enums.Operation.DESTROY),
                contents.Operation(enums.Operation.QUERY)
            ])

            if self._protocol_version == contents.ProtocolVersion.create(1, 1):
                operations.extend([
                    contents.Operation(enums.Operation.DISCOVER_VERSIONS)
                ])

        if enums.QueryFunction.QUERY_OBJECTS in queries:
            objects = list()
        if enums.QueryFunction.QUERY_SERVER_INFORMATION in queries:
            vendor_identification = misc.VendorIdentification(
                "PyKMIP {0} Software Server".format(kmip.__version__)
            )
            server_information = None
        if enums.QueryFunction.QUERY_APPLICATION_NAMESPACES in queries:
            namespaces = list()
        if enums.QueryFunction.QUERY_EXTENSION_LIST in queries:
            extensions = list()
        if enums.QueryFunction.QUERY_EXTENSION_MAP in queries:
            extensions = list()

        response_payload = query.QueryResponsePayload(
            operations=operations,
            object_types=objects,
            vendor_identification=vendor_identification,
            server_information=server_information,
            application_namespaces=namespaces,
            extension_information=extensions
        )

        return response_payload

    @_kmip_version_supported('1.1')
    def _process_discover_versions(self, payload):
        self._logger.info("Processing operation: DiscoverVersions")
        supported_versions = list()

        if len(payload.protocol_versions) > 0:
            for version in payload.protocol_versions:
                if version in self._protocol_versions:
                    supported_versions.append(version)
        else:
            supported_versions = self._protocol_versions

        response_payload = discover_versions.DiscoverVersionsResponsePayload(
            protocol_versions=supported_versions
        )

        return response_payload