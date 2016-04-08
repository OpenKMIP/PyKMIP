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
import six
import sqlalchemy

from sqlalchemy.orm import exc

import threading
import time

import kmip

from kmip.core import attributes
from kmip.core import enums
from kmip.core import exceptions
from kmip.core.factories import secrets

from kmip.core import objects as core_objects

from kmip.core.messages import contents
from kmip.core.messages import messages

from kmip.core.messages.payloads import create
from kmip.core.messages.payloads import create_key_pair
from kmip.core.messages.payloads import destroy
from kmip.core.messages.payloads import discover_versions
from kmip.core.messages.payloads import get
from kmip.core.messages.payloads import query
from kmip.core.messages.payloads import register

from kmip.core import misc

from kmip.pie import factory
from kmip.pie import objects
from kmip.pie import sqltypes

from kmip.services.server import policy
from kmip.services.server.crypto import engine


class KmipEngine(object):
    """
    A KMIP request processor that acts as the core of the KmipServer.

    The KmipEngine contains the core application logic for the KmipServer.
    It processes all KMIP requests and maintains consistent state across
    client connections.

    Features that are not supported:
        * KMIP versions > 1.2
        * Numerous operations, objects, and attributes.
        * User authentication
        * Batch processing options: UNDO
        * Asynchronous operations
        * Operation policies
        * Object archival
        * Key compression
        * Key wrapping
        * Key format conversions
        * Registration of empty managed objects (e.g., Private Keys)
        * Managed object state tracking
        * Managed object usage limit tracking and enforcement
        * Cryptographic usage mask enforcement per object type
    """

    def __init__(self):
        """
        Create a KmipEngine.
        """
        self._logger = logging.getLogger('kmip.server.engine')

        self._cryptography_engine = engine.CryptographyEngine()

        self._data_store = sqlalchemy.create_engine(
            'sqlite:////tmp/pykmip.database',
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

        self._attribute_policy = policy.AttributePolicy(self._protocol_version)
        self._attribute_factory = factory.AttributeFactory()

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
            self._attribute_policy = policy.AttributePolicy(
                self._protocol_version
            )
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

    def _get_object_type(self, unique_identifier):
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

        class_type = self._object_map.get(object_type)
        if class_type is None:
            name = object_type.name
            raise exceptions.InvalidField(
                "The {0} object type is not supported.".format(
                    ''.join(
                        [x.capitalize() for x in name.split('_')]
                    )
                )
            )

        return class_type

    def _build_core_object(self, obj):
        try:
            object_type = obj._object_type
        except Exception:
            raise exceptions.InvalidField(
                "Cannot build an unsupported object type."
            )

        value = {}

        if object_type == enums.ObjectType.CERTIFICATE:
            value = {
                'certificate_type': obj.certificate_type,
                'certificate_value': obj.value
            }
        elif object_type == enums.ObjectType.SYMMETRIC_KEY:
            value = {
                'cryptographic_algorithm': obj.cryptographic_algorithm,
                'cryptographic_length': obj.cryptographic_length,
                'key_format_type': obj.key_format_type,
                'key_value': obj.value
            }
        elif object_type == enums.ObjectType.PUBLIC_KEY:
            value = {
                'cryptographic_algorithm': obj.cryptographic_algorithm,
                'cryptographic_length': obj.cryptographic_length,
                'key_format_type': obj.key_format_type,
                'key_value': obj.value
            }
        elif object_type == enums.ObjectType.PRIVATE_KEY:
            value = {
                'cryptographic_algorithm': obj.cryptographic_algorithm,
                'cryptographic_length': obj.cryptographic_length,
                'key_format_type': obj.key_format_type,
                'key_value': obj.value
            }
        elif object_type == enums.ObjectType.SECRET_DATA:
            value = {
                'key_format_type': enums.KeyFormatType.OPAQUE,
                'key_value': obj.value,
                'secret_data_type': obj.data_type
            }
        elif object_type == enums.ObjectType.OPAQUE_DATA:
            value = {
                'opaque_data_type': obj.opaque_type,
                'opaque_data_value': obj.value
            }
        else:
            name = object_type.name
            raise exceptions.InvalidField(
                "The {0} object type is not supported.".format(
                    ''.join(
                        [x.capitalize() for x in name.split('_')]
                    )
                )
            )

        secret_factory = secrets.SecretFactory()
        return secret_factory.create(object_type, value)

    def _process_template_attribute(self, template_attribute):
        """
        Given a kmip.core TemplateAttribute object, extract the attribute
        value data into a usable dictionary format.
        """
        attributes = {}

        if len(template_attribute.names) > 0:
            raise exceptions.ItemNotFound(
                "Attribute templates are not supported."
            )

        for attribute in template_attribute.attributes:
            name = attribute.attribute_name.value

            if not self._attribute_policy.is_attribute_supported(name):
                raise exceptions.InvalidField(
                    "The {0} attribute is unsupported.".format(name)
                )

            if self._attribute_policy.is_attribute_multivalued(name):
                values = attributes.get(name, list())
                if (not attribute.attribute_index) and len(values) > 0:
                    raise exceptions.InvalidField(
                        "Attribute index missing from multivalued attribute."
                    )

                values.append(attribute.attribute_value)
                attributes.update([(name, values)])
            else:
                if attribute.attribute_index:
                    if attribute.attribute_index.value != 0:
                        raise exceptions.InvalidField(
                            "Non-zero attribute index found for "
                            "single-valued attribute."
                        )
                value = attributes.get(name, None)
                if value:
                    raise exceptions.IndexOutOfBounds(
                        "Cannot set multiple instances of the "
                        "{0} attribute.".format(name)
                    )
                else:
                    attributes.update([(name, attribute.attribute_value)])

        return attributes

    def _set_attributes_on_managed_object(self, managed_object, attributes):
        """
        Given a kmip.pie object and a dictionary of attributes, attempt to set
        the attribute values on the object.
        """
        for attribute_name, attribute_value in six.iteritems(attributes):
            object_type = managed_object._object_type
            if self._attribute_policy.is_attribute_applicable_to_object_type(
                    attribute_name,
                    object_type):
                self._set_attribute_on_managed_object(
                    managed_object,
                    (attribute_name, attribute_value)
                )
            else:
                name = object_type.name
                raise exceptions.InvalidField(
                    "Cannot set {0} attribute on {1} object.".format(
                        attribute_name,
                        ''.join([x.capitalize() for x in name.split('_')])
                    )
                )

    def _set_attribute_on_managed_object(self, managed_object, attribute):
        """
        Set the attribute value on the kmip.pie managed object.
        """
        attribute_name = attribute[0]
        attribute_value = attribute[1]

        if self._attribute_policy.is_attribute_multivalued(attribute_name):
            if attribute_name == 'Name':
                managed_object.names.extend(
                    [x.name_value.value for x in attribute_value]
                )
                for name in managed_object.names:
                    if managed_object.names.count(name) > 1:
                        raise exceptions.InvalidField(
                            "Cannot set duplicate name values."
                        )
            else:
                # TODO (peterhamilton) Remove when all attributes are supported
                raise exceptions.InvalidField(
                    "The {0} attribute is unsupported.".format(attribute_name)
                )
        else:
            field = None
            value = attribute_value.value

            if attribute_name == 'Cryptographic Algorithm':
                field = 'cryptographic_algorithm'
            elif attribute_name == 'Cryptographic Length':
                field = 'cryptographic_length'
            elif attribute_name == 'Cryptographic Usage Mask':
                field = 'cryptographic_usage_masks'
                value = list()
                for e in enums.CryptographicUsageMask:
                    if e.value & attribute_value.value:
                        value.append(e)

            if field:
                existing_value = getattr(managed_object, field)
                if existing_value:
                    if existing_value != value:
                        raise exceptions.InvalidField(
                            "Cannot overwrite the {0} attribute.".format(
                                attribute_name
                            )
                        )
                else:
                    setattr(managed_object, field, value)
            else:
                # TODO (peterhamilton) Remove when all attributes are supported
                raise exceptions.InvalidField(
                    "The {0} attribute is unsupported.".format(attribute_name)
                )

    def _process_operation(self, operation, payload):
        if operation == enums.Operation.CREATE:
            return self._process_create(payload)
        elif operation == enums.Operation.CREATE_KEY_PAIR:
            return self._process_create_key_pair(payload)
        elif operation == enums.Operation.REGISTER:
            return self._process_register(payload)
        elif operation == enums.Operation.GET:
            return self._process_get(payload)
        elif operation == enums.Operation.DESTROY:
            return self._process_destroy(payload)
        elif operation == enums.Operation.QUERY:
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
    def _process_create(self, payload):
        self._logger.info("Processing operation: Create")

        object_type = payload.object_type.value
        template_attribute = payload.template_attribute

        if object_type != enums.ObjectType.SYMMETRIC_KEY:
            name = object_type.name
            raise exceptions.InvalidField(
                "Cannot create a {0} object with the Create operation.".format(
                    ''.join([x.capitalize() for x in name.split('_')])
                )
            )

        object_attributes = {}
        if template_attribute:
            object_attributes = self._process_template_attribute(
                template_attribute
            )

        algorithm = object_attributes.get('Cryptographic Algorithm')
        if algorithm:
            algorithm = algorithm.value
        else:
            raise exceptions.InvalidField(
                "The cryptographic algorithm must be specified as an "
                "attribute."
            )

        length = None
        requested_length = object_attributes.get('Cryptographic Length')
        if requested_length is not None:
            length = requested_length.value

        usage_mask = object_attributes.get('Cryptographic Usage Mask')
        if usage_mask is None:
            raise exceptions.InvalidField(
                "The cryptographic usage mask must be specified as an "
                "attribute."
            )

        result = self._cryptography_engine.create_symmetric_key(
            algorithm,
            length
        )
        length = result['cryptographic_length']

        managed_object = objects.SymmetricKey(
            algorithm,
            length,
            result.get('value')
        )
        managed_object.names = []

        self._set_attributes_on_managed_object(
            managed_object,
            object_attributes
        )

        # TODO (peterhamilton) Set additional server-only attributes.

        self._data_session.add(managed_object)

        # NOTE (peterhamilton) SQLAlchemy will *not* assign an ID until
        # commit is called. This makes future support for UNDO problematic.
        self._data_session.commit()

        self._logger.info(
            "Created a SymmetricKey with ID: {0}".format(
                managed_object.unique_identifier
            )
        )

        ret_attributes = []
        template_attribute = None
        if requested_length is None:
            crypto_length_attribute = self._attribute_factory.create_attribute(
                enums.AttributeType.CRYPTOGRAPHIC_LENGTH,
                length)
            ret_attributes.append(crypto_length_attribute)

        if len(ret_attributes) > 0:
            template_attribute = core_objects.TemplateAttribute(
                attributes=ret_attributes)

        response_payload = create.CreateResponsePayload(
            object_type=payload.object_type,
            unique_identifier=attributes.UniqueIdentifier(
                str(managed_object.unique_identifier)
            ),
            template_attribute=template_attribute
        )

        self._id_placeholder = str(managed_object.unique_identifier)

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_create_key_pair(self, payload):
        self._logger.info("Processing operation: CreateKeyPair")

        algorithm = None
        length = None

        # Process attribute sets
        public_key_attributes = {}
        private_key_attributes = {}
        common_attributes = {}
        if payload.public_key_template_attribute:
            public_key_attributes = self._process_template_attribute(
                payload.public_key_template_attribute
            )
        if payload.private_key_template_attribute:
            private_key_attributes = self._process_template_attribute(
                payload.private_key_template_attribute
            )
        if payload.common_template_attribute:
            common_attributes = self._process_template_attribute(
                payload.common_template_attribute
            )

        # Propagate common attributes if not overridden by the public/private
        # attribute sets
        for key, value in six.iteritems(common_attributes):
            if key not in public_key_attributes.keys():
                public_key_attributes.update([(key, value)])
            if key not in private_key_attributes.keys():
                private_key_attributes.update([(key, value)])

        # Error check for required attributes.
        public_algorithm = public_key_attributes.get('Cryptographic Algorithm')
        if public_algorithm:
            public_algorithm = public_algorithm.value
        else:
            raise exceptions.InvalidField(
                "The cryptographic algorithm must be specified as an "
                "attribute for the public key."
            )

        public_length = public_key_attributes.get('Cryptographic Length')
        if public_length:
            public_length = public_length.value
        else:
            # TODO (peterhamilton) The cryptographic length is technically not
            # required per the spec. Update the CryptographyEngine to accept a
            # None length, allowing it to pick the length dynamically. Default
            # to the strongest key size allowed for the algorithm type.
            raise exceptions.InvalidField(
                "The cryptographic length must be specified as an attribute "
                "for the public key."
            )

        public_usage_mask = public_key_attributes.get(
            'Cryptographic Usage Mask'
        )
        if public_usage_mask is None:
            raise exceptions.InvalidField(
                "The cryptographic usage mask must be specified as an "
                "attribute for the public key."
            )

        private_algorithm = private_key_attributes.get(
            'Cryptographic Algorithm'
        )
        if private_algorithm:
            private_algorithm = private_algorithm.value
        else:
            raise exceptions.InvalidField(
                "The cryptographic algorithm must be specified as an "
                "attribute for the private key."
            )

        private_length = private_key_attributes.get('Cryptographic Length')
        if private_length:
            private_length = private_length.value
        else:
            # TODO (peterhamilton) The cryptographic length is technically not
            # required per the spec. Update the CryptographyEngine to accept a
            # None length, allowing it to pick the length dynamically. Default
            # to the strongest key size allowed for the algorithm type.
            raise exceptions.InvalidField(
                "The cryptographic length must be specified as an attribute "
                "for the private key."
            )

        private_usage_mask = private_key_attributes.get(
            'Cryptographic Usage Mask'
        )
        if private_usage_mask is None:
            raise exceptions.InvalidField(
                "The cryptographic usage mask must be specified as an "
                "attribute for the private key."
            )

        if public_algorithm == private_algorithm:
            algorithm = public_algorithm
        else:
            raise exceptions.InvalidField(
                "The public and private key algorithms must be the same."
            )

        if public_length == private_length:
            length = public_length
        else:
            raise exceptions.InvalidField(
                "The public and private key lengths must be the same."
            )

        public, private = self._cryptography_engine.create_asymmetric_key_pair(
            algorithm,
            length
        )

        public_key = objects.PublicKey(
            algorithm,
            length,
            public.get('value'),
            public.get('format')
        )
        private_key = objects.PrivateKey(
            algorithm,
            length,
            private.get('value'),
            private.get('format')
        )
        public_key.names = []
        private_key.names = []

        self._set_attributes_on_managed_object(
            public_key,
            public_key_attributes
        )
        self._set_attributes_on_managed_object(
            private_key,
            private_key_attributes
        )

        # TODO (peterhamilton) Set additional server-only attributes.

        self._data_session.add(public_key)
        self._data_session.add(private_key)

        # NOTE (peterhamilton) SQLAlchemy will *not* assign an ID until
        # commit is called. This makes future support for UNDO problematic.
        self._data_session.commit()

        self._logger.info(
            "Created a PublicKey with ID: {0}".format(
                public_key.unique_identifier
            )
        )
        self._logger.info(
            "Created a PrivateKey with ID: {0}".format(
                private_key.unique_identifier
            )
        )

        response_payload = create_key_pair.CreateKeyPairResponsePayload(
            private_key_uuid=attributes.PrivateKeyUniqueIdentifier(
                str(private_key.unique_identifier)
            ),
            public_key_uuid=attributes.PublicKeyUniqueIdentifier(
                str(public_key.unique_identifier)
            )
        )

        self._id_placeholder = str(private_key.unique_identifier)
        return response_payload

    @_kmip_version_supported('1.0')
    def _process_register(self, payload):
        self._logger.info("Processing operation: Register")

        object_type = payload.object_type.value
        template_attribute = payload.template_attribute

        if self._object_map.get(object_type) is None:
            name = object_type.name
            raise exceptions.InvalidField(
                "The {0} object type is not supported.".format(
                    ''.join(
                        [x.capitalize() for x in name.split('_')]
                    )
                )
            )

        if payload.secret:
            secret = payload.secret
        else:
            # TODO (peterhamilton) It is possible to register 'empty' secrets
            # like Private Keys. For now, that feature is not supported.
            raise exceptions.InvalidField(
                "Cannot register a secret in absentia."
            )

        object_attributes = {}
        if template_attribute:
            object_attributes = self._process_template_attribute(
                template_attribute
            )

        managed_object_factory = factory.ObjectFactory()
        managed_object = managed_object_factory.convert(secret)
        managed_object.names = []

        self._set_attributes_on_managed_object(
            managed_object,
            object_attributes
        )

        # TODO (peterhamilton) Set additional server-only attributes.

        self._data_session.add(managed_object)

        # NOTE (peterhamilton) SQLAlchemy will *not* assign an ID until
        # commit is called. This makes future support for UNDO problematic.
        self._data_session.commit()

        self._logger.info(
            "Registered a {0} with ID: {1}".format(
                ''.join([x.capitalize() for x in object_type.name.split('_')]),
                managed_object.unique_identifier
            )
        )

        response_payload = register.RegisterResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(
                str(managed_object.unique_identifier)
            )
        )

        self._id_placeholder = str(managed_object.unique_identifier)

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_get(self, payload):
        self._logger.info("Processing operation: Get")

        unique_identifier = self._id_placeholder
        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier.value

        key_format_type = None
        if payload.key_format_type:
            key_format_type = payload.key_format_type.value

        if payload.key_compression_type:
            raise exceptions.KeyCompressionTypeNotSupported(
                "Key compression is not supported."
            )

        if payload.key_wrapping_specification:
            raise exceptions.PermissionDenied(
                "Key wrapping is not supported."
            )

        # TODO (peterhamilton) Process key wrapping information
        # 1. Error check wrapping keys for accessibility and usability

        object_type = self._get_object_type(unique_identifier)

        managed_object = self._data_session.query(object_type).filter(
            object_type.unique_identifier == unique_identifier
        ).one()

        if key_format_type:
            if not hasattr(managed_object, 'key_format_type'):
                raise exceptions.KeyFormatTypeNotSupported(
                    "Key format is not applicable to the specified object."
                )

            # TODO (peterhamilton) Convert key to desired format if possible
            if key_format_type != managed_object.key_format_type:
                raise exceptions.KeyFormatTypeNotSupported(
                    "Key format conversion from {0} to {1} is "
                    "unsupported.".format(
                        managed_object.key_format_type.name,
                        key_format_type.name
                    )
                )

        object_type = managed_object.object_type.name
        self._logger.info(
            "Getting a {0} with ID: {1}".format(
                ''.join([x.capitalize() for x in object_type.split('_')]),
                managed_object.unique_identifier
            )
        )

        core_secret = self._build_core_object(managed_object)

        response_payload = get.GetResponsePayload(
            object_type=attributes.ObjectType(managed_object._object_type),
            unique_identifier=attributes.UniqueIdentifier(unique_identifier),
            secret=core_secret
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_destroy(self, payload):
        self._logger.info("Processing operation: Destroy")

        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier.value
        else:
            unique_identifier = self._id_placeholder

        self._get_object_type(unique_identifier)

        # TODO (peterhamilton) Process attributes to see if destroy possible
        # 1. Check object state. If invalid, error out.
        # 2. Check object deactivation date. If invalid, error out.

        self._logger.info(
            "Destroying an object with ID: {0}".format(unique_identifier)
        )

        self._data_session.query(objects.ManagedObject).filter(
            objects.ManagedObject.unique_identifier == unique_identifier
        ).delete()

        response_payload = destroy.DestroyResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(unique_identifier)
        )

        self._data_session.commit()

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
                contents.Operation(enums.Operation.CREATE),
                contents.Operation(enums.Operation.CREATE_KEY_PAIR),
                contents.Operation(enums.Operation.REGISTER),
                contents.Operation(enums.Operation.GET),
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
