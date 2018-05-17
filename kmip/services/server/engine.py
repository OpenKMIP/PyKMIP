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

import copy
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

from kmip.core.objects import MACData, KeyWrappingData

from kmip.core.factories import attributes as attribute_factory
from kmip.core.factories import secrets

from kmip.core.messages import contents
from kmip.core.messages import messages

from kmip.core.messages import payloads

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

    def __init__(self, policies=None, database_path=None):
        """
        Create a KmipEngine.

        Args:
            policy_path (string): The path to the filesystem directory
                containing PyKMIP server operation policy JSON files.
                Optional, defaults to None.
            database_path (string): The path to the SQLite database file
                used to store all server data. Optional, defaults to None.
                If none, database path defaults to '/tmp/pykmip.database'.
        """
        self._logger = logging.getLogger('kmip.server.engine')

        self._cryptography_engine = engine.CryptographyEngine()

        self.database_path = 'sqlite:///{}'.format(database_path)
        if not database_path:
            self.database_path = 'sqlite:////tmp/pykmip.database'

        self._data_store = sqlalchemy.create_engine(
            self.database_path,
            echo=False,
            connect_args={'check_same_thread': False}
        )
        sqltypes.Base.metadata.create_all(self._data_store)
        self._data_store_session_factory = sqlalchemy.orm.sessionmaker(
            bind=self._data_store
        )

        self._lock = threading.RLock()

        self._id_placeholder = None

        self._protocol_versions = [
            contents.ProtocolVersion(1, 2),
            contents.ProtocolVersion(1, 1),
            contents.ProtocolVersion(1, 0)
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
        self._operation_policies = policies
        self._client_identity = [None, None]

    def _get_enum_string(self, e):
        return ''.join([x.capitalize() for x in e.name.split('_')])

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
        # TODO (peterhamilton) Improve authentication support
        # 1. If present, verify user ID of connection_credential is valid user.
        # 2. If present, verify request_credential is valid credential.
        # 3. If both present, verify that they are compliant with each other.
        # 4. If neither present, set server to only allow Query operations.

        # For now, simply use the connection_credential as received. It was
        # obtained from a valid client certificate, so consider it a trusted
        # form of client identity.
        self._client_identity = connection_credential

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
            credential (string): Identifying information about the client
                obtained from the client certificate. Optional, defaults to
                None.

        Returns:
            ResponseMessage: The response containing all of the results from
                the request batch items.
        """
        self._client_identity = [None, None]
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
        if header.authentication:
            if header.authentication.credentials:
                auth_credentials = header.authentication.credentials[0]
            else:
                auth_credentials = None
        else:
            auth_credentials = None

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
                'key_value': obj.value,
                'key_wrapping_data': obj.key_wrapping_data
            }
        elif object_type == enums.ObjectType.PUBLIC_KEY:
            value = {
                'cryptographic_algorithm': obj.cryptographic_algorithm,
                'cryptographic_length': obj.cryptographic_length,
                'key_format_type': obj.key_format_type,
                'key_value': obj.value,
                'key_wrapping_data': obj.key_wrapping_data
            }
        elif object_type == enums.ObjectType.PRIVATE_KEY:
            value = {
                'cryptographic_algorithm': obj.cryptographic_algorithm,
                'cryptographic_length': obj.cryptographic_length,
                'key_format_type': obj.key_format_type,
                'key_value': obj.value,
                'key_wrapping_data': obj.key_wrapping_data
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

    def _get_attributes_from_managed_object(self, managed_object, attr_names):
        """
        Given a kmip.pie object and a list of attribute names, attempt to get
        all of the existing attribute values from the object.
        """
        attr_factory = attribute_factory.AttributeFactory()
        retrieved_attributes = list()

        if not attr_names:
            attr_names = self._attribute_policy.get_all_attribute_names()

        for attribute_name in attr_names:
            object_type = managed_object._object_type

            if not self._attribute_policy.is_attribute_supported(
                    attribute_name
            ):
                continue

            if self._attribute_policy.is_attribute_applicable_to_object_type(
                attribute_name,
                object_type
            ):
                try:
                    attribute_value = self._get_attribute_from_managed_object(
                        managed_object,
                        attribute_name
                    )
                except Exception:
                    attribute_value = None

                if attribute_value is not None:
                    if self._attribute_policy.is_attribute_multivalued(
                            attribute_name
                    ):
                        for count, value in enumerate(attribute_value):
                            attribute = attr_factory.create_attribute(
                                enums.AttributeType(attribute_name),
                                value,
                                count
                            )
                            retrieved_attributes.append(attribute)
                    else:
                        attribute = attr_factory.create_attribute(
                            enums.AttributeType(attribute_name),
                            attribute_value
                        )
                        retrieved_attributes.append(attribute)

        return retrieved_attributes

    def _get_attribute_from_managed_object(self, managed_object, attr_name):
        """
        Get the attribute value from the kmip.pie managed object.
        """
        if attr_name == 'Unique Identifier':
            return str(managed_object.unique_identifier)
        elif attr_name == 'Name':
            names = list()
            for name in managed_object.names:
                name = attributes.Name(
                    attributes.Name.NameValue(name),
                    attributes.Name.NameType(
                        enums.NameType.UNINTERPRETED_TEXT_STRING
                    )
                )
                names.append(name)
            return names
        elif attr_name == 'Object Type':
            return managed_object._object_type
        elif attr_name == 'Cryptographic Algorithm':
            return managed_object.cryptographic_algorithm
        elif attr_name == 'Cryptographic Length':
            return managed_object.cryptographic_length
        elif attr_name == 'Cryptographic Parameters':
            return None
        elif attr_name == 'Cryptographic Domain Parameters':
            return None
        elif attr_name == 'Certificate Type':
            return managed_object.certificate_type
        elif attr_name == 'Certificate Length':
            return None
        elif attr_name == 'X.509 Certificate Identifier':
            return None
        elif attr_name == 'X.509 Certificate Subject':
            return None
        elif attr_name == 'X.509 Certificate Issuer':
            return None
        elif attr_name == 'Certificate Identifier':
            return None
        elif attr_name == 'Certificate Subject':
            return None
        elif attr_name == 'Certificate Issuer':
            return None
        elif attr_name == 'Digital Signature Algorithm':
            return None
        elif attr_name == 'Digest':
            return None
        elif attr_name == 'Operation Policy Name':
            return managed_object.operation_policy_name
        elif attr_name == 'Cryptographic Usage Mask':
            return managed_object.cryptographic_usage_masks
        elif attr_name == 'Lease Time':
            return None
        elif attr_name == 'Usage Limits':
            return None
        elif attr_name == 'State':
            return managed_object.state
        elif attr_name == 'Initial Date':
            return managed_object.initial_date
        elif attr_name == 'Activation Date':
            return None
        elif attr_name == 'Process Start Date':
            return None
        elif attr_name == 'Protect Stop Date':
            return None
        elif attr_name == 'Deactivation Date':
            return None
        elif attr_name == 'Destroy Date':
            return None
        elif attr_name == 'Compromise Occurrence Date':
            return None
        elif attr_name == 'Compromise Date':
            return None
        elif attr_name == 'Revocation Reason':
            return None
        elif attr_name == 'Archive Date':
            return None
        elif attr_name == 'Object Group':
            return None
        elif attr_name == 'Fresh':
            return None
        elif attr_name == 'Link':
            return None
        elif attr_name == 'Application Specific Information':
            return None
        elif attr_name == 'Contact Information':
            return None
        elif attr_name == 'Last Change Date':
            return None
        else:
            # Since custom attribute names are possible, just return None
            # for unrecognized attributes. This satisfies the spec.
            return None

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
            elif attribute_name == 'Operation Policy Name':
                field = 'operation_policy_name'

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

    def _is_allowed_by_operation_policy(
            self,
            policy_name,
            session_identity,
            object_owner,
            object_type,
            operation
    ):
        session_user = session_identity[0]
        session_groups = session_identity[1]

        if session_groups is None:
            session_groups = [None]

        for session_group in session_groups:
            allowed = self.is_allowed(
                policy_name,
                session_user,
                session_group,
                object_owner,
                object_type,
                operation
            )
            if allowed:
                return True

        return False

    def get_relevant_policy_section(self, policy_name, group=None):
        """
        Look up the policy corresponding to the provided policy name and
        group (optional). Log any issues found during the look up.
        """
        policy_bundle = self._operation_policies.get(policy_name)

        if not policy_bundle:
            self._logger.warning(
                "The '{}' policy does not exist.".format(policy_name)
            )
            return None

        if group:
            groups_policy_bundle = policy_bundle.get('groups')
            if not groups_policy_bundle:
                self._logger.debug(
                    "The '{}' policy does not support groups.".format(
                        policy_name
                    )
                )
                return None
            else:
                group_policy = groups_policy_bundle.get(group)
                if not group_policy:
                    self._logger.debug(
                        "The '{}' policy does not support group '{}'.".format(
                            policy_name,
                            group
                        )
                    )
                    return None
                else:
                    return group_policy
        else:
            return policy_bundle.get('preset')

    def is_allowed(
            self,
            policy_name,
            session_user,
            session_group,
            object_owner,
            object_type,
            operation
    ):
        """
        Determine if object access is allowed for the provided policy and
        session settings.
        """
        policy_section = self.get_relevant_policy_section(
            policy_name,
            session_group
        )
        if policy_section is None:
            return False

        object_policy = policy_section.get(object_type)
        if not object_policy:
            self._logger.warning(
                "The '{0}' policy does not apply to {1} objects.".format(
                    policy_name,
                    self._get_enum_string(object_type)
                )
            )
            return False

        operation_object_policy = object_policy.get(operation)
        if not operation_object_policy:
            self._logger.warning(
                "The '{0}' policy does not apply to {1} operations on {2} "
                "objects.".format(
                    policy_name,
                    self._get_enum_string(operation),
                    self._get_enum_string(object_type)
                )
            )
            return False

        if operation_object_policy == enums.Policy.ALLOW_ALL:
            return True
        elif operation_object_policy == enums.Policy.ALLOW_OWNER:
            if session_user == object_owner:
                return True
            else:
                return False
        elif operation_object_policy == enums.Policy.DISALLOW_ALL:
            return False
        else:
            return False

    def _get_object_with_access_controls(
            self,
            uid,
            operation
    ):
        object_type = self._get_object_type(uid)

        managed_object = self._data_session.query(object_type).filter(
            object_type.unique_identifier == uid
        ).one()

        # TODO (peter-hamilton) Add debug log with policy contents?

        # Determine if the request should be carried out under the object's
        # operation policy. If not, feign ignorance of the object.
        is_allowed = self._is_allowed_by_operation_policy(
            managed_object.operation_policy_name,
            self._client_identity,
            managed_object._owner,
            managed_object.object_type,
            operation
        )
        if not is_allowed:
            raise exceptions.PermissionDenied(
                "Could not locate object: {0}".format(uid)
            )

        return managed_object

    def _list_objects_with_access_controls(
            self,
            operation
    ):
        managed_objects = None
        managed_objects_allowed = list()

        managed_objects = self._data_session.query(objects.ManagedObject).all()

        for managed_object in managed_objects:
            is_allowed = self._is_allowed_by_operation_policy(
                managed_object.operation_policy_name,
                self._client_identity,
                managed_object._owner,
                managed_object.object_type,
                operation
            )
            if is_allowed is True:
                managed_objects_allowed.append(managed_object)

        return managed_objects_allowed

    def _process_operation(self, operation, payload):
        if operation == enums.Operation.CREATE:
            return self._process_create(payload)
        elif operation == enums.Operation.CREATE_KEY_PAIR:
            return self._process_create_key_pair(payload)
        elif operation == enums.Operation.REGISTER:
            return self._process_register(payload)
        elif operation == enums.Operation.DERIVE_KEY:
            return self._process_derive_key(payload)
        elif operation == enums.Operation.LOCATE:
            return self._process_locate(payload)
        elif operation == enums.Operation.GET:
            return self._process_get(payload)
        elif operation == enums.Operation.GET_ATTRIBUTES:
            return self._process_get_attributes(payload)
        elif operation == enums.Operation.GET_ATTRIBUTE_LIST:
            return self._process_get_attribute_list(payload)
        elif operation == enums.Operation.ACTIVATE:
            return self._process_activate(payload)
        elif operation == enums.Operation.REVOKE:
            return self._process_revoke(payload)
        elif operation == enums.Operation.DESTROY:
            return self._process_destroy(payload)
        elif operation == enums.Operation.QUERY:
            return self._process_query(payload)
        elif operation == enums.Operation.DISCOVER_VERSIONS:
            return self._process_discover_versions(payload)
        elif operation == enums.Operation.ENCRYPT:
            return self._process_encrypt(payload)
        elif operation == enums.Operation.DECRYPT:
            return self._process_decrypt(payload)
        elif operation == enums.Operation.SIGNATURE_VERIFY:
            return self._process_signature_verify(payload)
        elif operation == enums.Operation.MAC:
            return self._process_mac(payload)
        elif operation == enums.Operation.SIGN:
            return self._process_sign(payload)
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

        length = object_attributes.get('Cryptographic Length')
        if length:
            length = length.value
        else:
            # TODO (peterhamilton) The cryptographic length is technically not
            # required per the spec. Update the CryptographyEngine to accept a
            # None length, allowing it to pick the length dynamically. Default
            # to the strongest key size allowed for the algorithm type.
            raise exceptions.InvalidField(
                "The cryptographic length must be specified as an attribute."
            )

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
        managed_object._owner = self._client_identity[0]
        managed_object.initial_date = int(time.time())

        self._data_session.add(managed_object)

        # NOTE (peterhamilton) SQLAlchemy will *not* assign an ID until
        # commit is called. This makes future support for UNDO problematic.
        self._data_session.commit()

        self._logger.info(
            "Created a SymmetricKey with ID: {0}".format(
                managed_object.unique_identifier
            )
        )

        response_payload = payloads.CreateResponsePayload(
            object_type=payload.object_type,
            unique_identifier=attributes.UniqueIdentifier(
                str(managed_object.unique_identifier)
            ),
            template_attribute=None
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
        public_key._owner = self._client_identity[0]
        public_key.initial_date = int(time.time())
        private_key._owner = self._client_identity[0]
        private_key.initial_date = public_key.initial_date

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

        response_payload = payloads.CreateKeyPairResponsePayload(
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
        managed_object._owner = self._client_identity[0]
        managed_object.initial_date = int(time.time())

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

        response_payload = payloads.RegisterResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(
                str(managed_object.unique_identifier)
            )
        )

        self._id_placeholder = str(managed_object.unique_identifier)

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_derive_key(self, payload):
        self._logger.info("Processing operation: DeriveKey")

        object_attributes = {}
        if payload.template_attribute:
            object_attributes = self._process_template_attribute(
                payload.template_attribute
            )

        if payload.object_type not in [
            enums.ObjectType.SYMMETRIC_KEY,
            enums.ObjectType.SECRET_DATA
        ]:
            raise exceptions.InvalidField(
                "Key derivation can only generate a SymmetricKey or "
                "SecretData object."
            )

        # Retrieve existing managed objects to be used in the key derivation
        # process. If any are unaccessible or not suitable for key derivation,
        # raise an error.
        existing_objects = []
        for unique_identifier in payload.unique_identifiers:
            managed_object = self._get_object_with_access_controls(
                unique_identifier,
                enums.Operation.GET
            )
            if managed_object._object_type not in [
                enums.ObjectType.SECRET_DATA,
                enums.ObjectType.SYMMETRIC_KEY,
                enums.ObjectType.PUBLIC_KEY,
                enums.ObjectType.PRIVATE_KEY
            ]:
                raise exceptions.InvalidField(
                    "Object {0} is not a suitable type for key "
                    "derivation. Please specify a key or secret data.".format(
                        unique_identifier
                    )
                )
            elif enums.CryptographicUsageMask.DERIVE_KEY not in \
                    managed_object.cryptographic_usage_masks:
                raise exceptions.InvalidField(
                    "The DeriveKey bit must be set in the cryptographic usage "
                    "mask for object {0} for it to be used in key "
                    "derivation.".format(unique_identifier)
                )
            else:
                existing_objects.append(managed_object)

        if len(existing_objects) > 1:
            self._logger.info(
                "{0} derivation objects specified with the DeriveKey "
                "request.".format(len(existing_objects))
            )

        # Select the derivation object to use as the keying material
        keying_object = existing_objects[0]
        self._logger.info(
            "Object {0} will be used as the keying material for the "
            "derivation process.".format(keying_object.unique_identifier)
        )

        derivation_parameters = payload.derivation_parameters

        derivation_data = None
        if derivation_parameters.derivation_data is None:
            if len(existing_objects) > 1:
                for alternate in existing_objects[1:]:
                    if alternate._object_type == enums.ObjectType.SECRET_DATA:
                        self._logger.info(
                            "Object {0} will be used as the derivation data "
                            "for the derivation process.".format(
                                alternate.unique_identifier
                            )
                        )
                        derivation_data = alternate.value
                        break
        else:
            derivation_data = derivation_parameters.derivation_data

        iv = b''
        if derivation_parameters.initialization_vector is not None:
            iv = derivation_parameters.initialization_vector

        # Get the derivation length from the template attribute. It is
        # required so if it cannot be found, raise an error.
        derivation_length = None
        attribute = object_attributes.get('Cryptographic Length')
        if attribute:
            derivation_length = attribute.value
            if (derivation_length % 8) == 0:
                derivation_length //= 8
            else:
                raise exceptions.InvalidField(
                    "The cryptographic length must correspond to a valid "
                    "number of bytes (i.e., it must be a multiple of 8)."
                )
        else:
            raise exceptions.InvalidField(
                "The cryptographic length must be provided in the template "
                "attribute."
            )

        cryptographic_algorithm = None
        if payload.object_type == enums.ObjectType.SYMMETRIC_KEY:
            attribute = object_attributes.get('Cryptographic Algorithm')
            if attribute:
                cryptographic_algorithm = attribute.value
            else:
                raise exceptions.InvalidField(
                    "The cryptographic algorithm must be provided in the "
                    "template attribute when deriving a symmetric key."
                )

        # TODO (peterhamilton): Pull cryptographic parameters from the keying
        # object if none are provided with the payload
        crypto_parameters = derivation_parameters.cryptographic_parameters
        derived_data = self._cryptography_engine.derive_key(
            derivation_method=payload.derivation_method,
            derivation_length=derivation_length,
            derivation_data=derivation_data,
            key_material=keying_object.value,
            hash_algorithm=crypto_parameters.hashing_algorithm,
            salt=derivation_parameters.salt,
            iteration_count=derivation_parameters.iteration_count,
            encryption_algorithm=crypto_parameters.cryptographic_algorithm,
            cipher_mode=crypto_parameters.block_cipher_mode,
            padding_method=crypto_parameters.padding_method,
            iv_nonce=iv
        )

        if derivation_length > len(derived_data):
            raise exceptions.CryptographicFailure(
                "The specified length exceeds the output of the derivation "
                "method."
            )
        if len(derived_data) > derivation_length:
            derived_data = derived_data[:derivation_length]

        if payload.object_type == enums.ObjectType.SYMMETRIC_KEY:
            managed_object = objects.SymmetricKey(
                algorithm=cryptographic_algorithm,
                length=(derivation_length * 8),
                value=derived_data,
            )
        else:
            managed_object = objects.SecretData(
                value=derived_data,
                data_type=enums.SecretDataType.SEED,
            )

        managed_object.names = []

        if payload.object_type == enums.ObjectType.SECRET_DATA:
            del object_attributes['Cryptographic Length']
        self._set_attributes_on_managed_object(
            managed_object,
            object_attributes
        )

        # TODO (peterhamilton) Set additional server-only attributes.
        managed_object._owner = self._client_identity[0]
        managed_object.initial_date = int(time.time())

        self._data_session.add(managed_object)
        self._data_session.commit()

        self._logger.info(
            "Created a {0} with ID: {1}".format(
                ''.join(
                    [x.capitalize() for x in
                     payload.object_type.name.split('_')]
                ),
                managed_object.unique_identifier
            )
        )
        self._id_placeholder = str(managed_object.unique_identifier)

        response_payload = payloads.DeriveKeyResponsePayload(
            unique_identifier=str(managed_object.unique_identifier)
        )
        return response_payload

    @_kmip_version_supported('1.0')
    def _process_locate(self, payload):
        # TODO: Need to complete the filtering logic based on all given
        # objects in payload.
        self._logger.info("Processing operation: Locate")

        managed_objects = self._list_objects_with_access_controls(
                                enums.Operation.LOCATE)

        if payload.attributes:

            managed_objects_filtered = []

            # Filter the objects based on given attributes.
            # TODO: Currently will only filter for 'Name'.
            #       Needs to add other attributes.
            for managed_object in managed_objects:
                for attribute in payload.attributes:
                    attribute_name = attribute.attribute_name.value
                    attribute_value = attribute.attribute_value
                    attr = self._get_attribute_from_managed_object(
                            managed_object, attribute_name)
                    if attribute_name == 'Name':
                        names = attr
                        if attribute_value not in names:
                                break
                    # TODO: filtering on other attributes
                else:
                    managed_objects_filtered.append(managed_object)

            managed_objects = managed_objects_filtered

        unique_identifiers = [attributes.UniqueIdentifier(
                            str(managed_object.unique_identifier))
                            for managed_object in managed_objects]

        response_payload = payloads.LocateResponsePayload(
            unique_identifiers=unique_identifiers
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_get(self, payload):
        self._logger.info("Processing operation: Get")

        unique_identifier = self._id_placeholder
        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier

        key_format_type = None
        if payload.key_format_type:
            key_format_type = payload.key_format_type

        if payload.key_compression_type:
            raise exceptions.KeyCompressionTypeNotSupported(
                "Key compression is not supported."
            )

        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET
        )

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

        if payload.key_wrapping_specification:
            key_wrapping_spec = payload.key_wrapping_specification
            wrapping_method = key_wrapping_spec.wrapping_method

            if wrapping_method != enums.WrappingMethod.ENCRYPT:
                raise exceptions.OperationNotSupported(
                    "Wrapping method '{0}' is not supported.".format(
                        wrapping_method
                    )
                )

            if key_wrapping_spec.encryption_key_information:
                key_info = key_wrapping_spec.encryption_key_information
                encryption_key_uuid = key_info.unique_identifier
                encryption_key_params = key_info.cryptographic_parameters

                try:
                    key = self._get_object_with_access_controls(
                        encryption_key_uuid,
                        enums.Operation.GET
                    )
                except Exception:
                    raise exceptions.ItemNotFound(
                        "Wrapping key does not exist."
                    )

                if key._object_type != enums.ObjectType.SYMMETRIC_KEY:
                    raise exceptions.IllegalOperation(
                        "The wrapping encryption key specified by the "
                        "encryption key information is not a key."
                    )

                if key.state != enums.State.ACTIVE:
                    raise exceptions.PermissionDenied(
                        "Encryption key {0} must be activated to be used for "
                        "key wrapping.".format(encryption_key_uuid)
                    )

                mask = enums.CryptographicUsageMask.WRAP_KEY
                if mask not in key.cryptographic_usage_masks:
                    raise exceptions.PermissionDenied(
                        "The WrapKey bit must be set in the cryptographic "
                        "usage mask of encryption key {0} for it to be used "
                        "for key wrapping.".format(encryption_key_uuid)
                    )

                if key_wrapping_spec.attribute_names:
                    raise exceptions.IllegalOperation(
                        "Wrapping object attributes is not supported."
                    )

                encoding_option = key_wrapping_spec.encoding_option
                if encoding_option != enums.EncodingOption.NO_ENCODING:
                    raise exceptions.EncodingOptionError(
                        "Encoding option '{0}' is not supported.".format(
                            encoding_option
                        )
                    )

                self._logger.info("Wrapping {0} {1} with {2} {3}.".format(
                    ''.join([x.capitalize() for x in object_type.split('_')]),
                    managed_object.unique_identifier,
                    ''.join(
                        [x.capitalize() for x in key._object_type.name.split(
                            '_'
                        )]
                    ),
                    encryption_key_uuid
                ))

                result = self._cryptography_engine.wrap_key(
                    key_material=managed_object.value,
                    wrapping_method=key_wrapping_spec.wrapping_method,
                    key_wrap_algorithm=encryption_key_params.block_cipher_mode,
                    encryption_key=key.value
                )

                wrapped_object = copy.deepcopy(managed_object)
                wrapped_object.value = result

                core_secret = self._build_core_object(wrapped_object)
                key_wrapping_data = KeyWrappingData(
                    wrapping_method=wrapping_method,
                    encryption_key_information=key_info,
                    encoding_option=encoding_option
                )
                core_secret.key_block.key_wrapping_data = key_wrapping_data

            elif key_wrapping_spec.mac_signature_key_information:
                raise exceptions.PermissionDenied(
                    "Key wrapping with MAC/signing key information is not "
                    "supported."
                )
            else:
                raise exceptions.PermissionDenied(
                    "Either the encryption key information or the "
                    "MAC/signature key information must be specified for key "
                    "wrapping to be performed."
                )
        else:
            core_secret = self._build_core_object(managed_object)

        response_payload = payloads.GetResponsePayload(
            object_type=managed_object._object_type,
            unique_identifier=unique_identifier,
            secret=core_secret
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_get_attributes(self, payload):
        self._logger.info("Processing operation: GetAttributes")

        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier
        else:
            unique_identifier = self._id_placeholder

        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET_ATTRIBUTES
        )
        attrs = self._get_attributes_from_managed_object(
            managed_object,
            payload.attribute_names
        )

        response_payload = payloads.GetAttributesResponsePayload(
            unique_identifier=unique_identifier,
            attributes=attrs
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_get_attribute_list(self, payload):
        self._logger.info("Processing operation: GetAttributeList")

        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier
        else:
            unique_identifier = self._id_placeholder

        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET_ATTRIBUTE_LIST
        )
        object_attributes = self._get_attributes_from_managed_object(
            managed_object,
            list()
        )
        attribute_names = list()

        for object_attribute in object_attributes:
            attribute_names.append(object_attribute.attribute_name.value)

        response_payload = payloads.GetAttributeListResponsePayload(
            unique_identifier=unique_identifier,
            attribute_names=attribute_names
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_activate(self, payload):
        self._logger.info("Processing operation: Activate")

        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier.value
        else:
            unique_identifier = self._id_placeholder

        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.ACTIVATE
        )
        object_type = managed_object._object_type
        if not hasattr(managed_object, 'state'):
            raise exceptions.IllegalOperation(
                "An {0} object has no state and cannot be activated.".format(
                    ''.join(
                        [x.capitalize() for x in object_type.name.split('_')]
                    )
                )
            )

        if managed_object.state != enums.State.PRE_ACTIVE:
            raise exceptions.PermissionDenied(
                "The object state is not pre-active and cannot be activated."
            )

        managed_object.state = enums.State.ACTIVE
        self._data_session.commit()

        response_payload = payloads.ActivateResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(unique_identifier)
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_revoke(self, payload):
        self._logger.info("Processing operation: Revoke")

        revocation_code = None
        if payload.revocation_reason and \
           payload.revocation_reason.revocation_code:
            revocation_code = payload.revocation_reason.revocation_code
        else:
            raise exceptions.InvalidField(
                "revocation reason code must be specified"
            )

        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier.value
        else:
            unique_identifier = self._id_placeholder

        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.REVOKE
        )
        object_type = managed_object._object_type
        if not hasattr(managed_object, 'state'):
            raise exceptions.IllegalOperation(
                "An {0} object has no state and cannot be revoked.".format(
                    ''.join(
                        [x.capitalize() for x in object_type.name.split('_')]
                    )
                )
            )

        # TODO: need to set Compromise Date attribute or Deactivation Date
        # attribute
        if revocation_code.value is enums.RevocationReasonCode.KEY_COMPROMISE:
            if managed_object.state == enums.State.DESTROYED:
                managed_object.state = enums.State.DESTROYED_COMPROMISED
            else:
                managed_object.state = enums.State.COMPROMISED
        else:
            if managed_object.state != enums.State.ACTIVE:
                raise exceptions.IllegalOperation(
                    "The object is not active and cannot be revoked with "
                    "reason other than KEY_COMPROMISE"
                )
            else:
                managed_object.state = enums.State.DEACTIVATED
        self._data_session.commit()

        response_payload = payloads.RevokeResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(unique_identifier)
        )

        return response_payload

    @_kmip_version_supported('1.0')
    def _process_destroy(self, payload):
        self._logger.info("Processing operation: Destroy")

        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier.value
        else:
            unique_identifier = self._id_placeholder

        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.DESTROY
        )

        # TODO If in "ACTIVE" state, we need to check its "Deactivation date"
        # to see whether it can be destroyed or not
        if hasattr(managed_object, 'state'):
            if managed_object.state == enums.State.ACTIVE:
                raise exceptions.PermissionDenied(
                    "Object is active and cannot be destroyed."
                )

        # 'OpaqueObject' object has no attribute 'state'
        if hasattr(managed_object, 'state') and \
           managed_object.state == enums.State.COMPROMISED:
            managed_object.state = enums.State.DESTROYED_COMPROMISED

        self._logger.info(
            "Destroying an object with ID: {0}".format(unique_identifier)
        )
        self._data_session.query(objects.ManagedObject).filter(
            objects.ManagedObject.unique_identifier == unique_identifier
        ).delete()

        response_payload = payloads.DestroyResponsePayload(
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
                contents.Operation(enums.Operation.DERIVE_KEY),
                contents.Operation(enums.Operation.LOCATE),
                contents.Operation(enums.Operation.GET),
                contents.Operation(enums.Operation.GET_ATTRIBUTES),
                contents.Operation(enums.Operation.GET_ATTRIBUTE_LIST),
                contents.Operation(enums.Operation.ACTIVATE),
                contents.Operation(enums.Operation.REVOKE),
                contents.Operation(enums.Operation.DESTROY),
                contents.Operation(enums.Operation.QUERY)
            ])

            if self._protocol_version >= contents.ProtocolVersion(1, 1):
                operations.extend([
                    contents.Operation(enums.Operation.DISCOVER_VERSIONS)
                ])
            if self._protocol_version >= contents.ProtocolVersion(1, 2):
                operations.extend([
                    contents.Operation(enums.Operation.ENCRYPT),
                    contents.Operation(enums.Operation.DECRYPT),
                    contents.Operation(enums.Operation.SIGN),
                    contents.Operation(enums.Operation.SIGNATURE_VERIFY),
                    contents.Operation(enums.Operation.MAC)
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

        response_payload = payloads.QueryResponsePayload(
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

        response_payload = payloads.DiscoverVersionsResponsePayload(
            protocol_versions=supported_versions
        )

        return response_payload

    @_kmip_version_supported('1.2')
    def _process_encrypt(self, payload):
        self._logger.info("Processing operation: Encrypt")

        unique_identifier = self._id_placeholder
        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier

        # The KMIP spec does not indicate that the Encrypt operation should
        # have it's own operation policy entry. Rather, the cryptographic
        # usage mask should be used to determine if the object can be used
        # to encrypt data (see below).
        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET
        )

        cryptographic_parameters = payload.cryptographic_parameters
        if cryptographic_parameters is None:
            # TODO (peter-hamilton): Pull the cryptographic parameters from
            # the attributes associated with the encryption key.
            raise exceptions.InvalidField(
                "The cryptographic parameters must be specified."
            )

        # TODO (peter-hamilton): Check the usage limitations for the key to
        # confirm that it can be used for this operation.

        if managed_object._object_type != enums.ObjectType.SYMMETRIC_KEY:
            raise exceptions.PermissionDenied(
                "The requested encryption key is not a symmetric key. "
                "Only symmetric encryption is currently supported."
            )

        if managed_object.state != enums.State.ACTIVE:
            raise exceptions.PermissionDenied(
                "The encryption key must be in the Active state to be used "
                "for encryption."
            )

        if enums.CryptographicUsageMask.ENCRYPT not in \
           managed_object.cryptographic_usage_masks:
                raise exceptions.PermissionDenied(
                    "The Encrypt bit must be set in the encryption key's "
                    "cryptographic usage mask."
                )

        result = self._cryptography_engine.encrypt(
            cryptographic_parameters.cryptographic_algorithm,
            managed_object.value,
            payload.data,
            cipher_mode=cryptographic_parameters.block_cipher_mode,
            padding_method=cryptographic_parameters.padding_method,
            iv_nonce=payload.iv_counter_nonce
        )

        response_payload = payloads.EncryptResponsePayload(
            unique_identifier,
            result.get('cipher_text'),
            result.get('iv_nonce')
        )
        return response_payload

    @_kmip_version_supported('1.2')
    def _process_decrypt(self, payload):
        self._logger.info("Processing operation: Decrypt")

        unique_identifier = self._id_placeholder
        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier

        # The KMIP spec does not indicate that the Decrypt operation should
        # have it's own operation policy entry. Rather, the cryptographic
        # usage mask should be used to determine if the object can be used
        # to decrypt data (see below).
        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET
        )

        cryptographic_parameters = payload.cryptographic_parameters
        if cryptographic_parameters is None:
            # TODO (peter-hamilton): Pull the cryptographic parameters from
            # the attributes associated with the decryption key.
            raise exceptions.InvalidField(
                "The cryptographic parameters must be specified."
            )

        # TODO (peter-hamilton): Check the usage limitations for the key to
        # confirm that it can be used for this operation.

        if managed_object._object_type != enums.ObjectType.SYMMETRIC_KEY:
            raise exceptions.PermissionDenied(
                "The requested decryption key is not a symmetric key. "
                "Only symmetric decryption is currently supported."
            )

        if managed_object.state != enums.State.ACTIVE:
            raise exceptions.PermissionDenied(
                "The decryption key must be in the Active state to be used "
                "for decryption."
            )

        if enums.CryptographicUsageMask.DECRYPT not in \
           managed_object.cryptographic_usage_masks:
                raise exceptions.PermissionDenied(
                    "The Decrypt bit must be set in the decryption key's "
                    "cryptographic usage mask."
                )

        result = self._cryptography_engine.decrypt(
            cryptographic_parameters.cryptographic_algorithm,
            managed_object.value,
            payload.data,
            cipher_mode=cryptographic_parameters.block_cipher_mode,
            padding_method=cryptographic_parameters.padding_method,
            iv_nonce=payload.iv_counter_nonce
        )

        response_payload = payloads.DecryptResponsePayload(
            unique_identifier,
            result
        )
        return response_payload

    @_kmip_version_supported('1.2')
    def _process_signature_verify(self, payload):
        self._logger.info("Processing operation: Signature Verify")

        unique_identifier = self._id_placeholder
        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier

        # The KMIP spec does not indicate that the SignatureVerify operation
        # should have it's own operation policy entry. Rather, the
        # cryptographic usage mask should be used to determine if the object
        # can be used to verify signatures (see below).
        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET
        )

        parameters = payload.cryptographic_parameters
        if parameters is None:
            # TODO (peter-hamilton): Pull the cryptographic parameters from
            # the attributes associated with the signing key.
            raise exceptions.InvalidField(
                "The cryptographic parameters must be specified."
            )

        # TODO (peter-hamilton): Check the usage limitations for the key to
        # confirm that it can be used for this operation.

        if managed_object._object_type != enums.ObjectType.PUBLIC_KEY:
            raise exceptions.PermissionDenied(
                "The requested signing key is not a public key. A public key "
                "must be specified."
            )

        if managed_object.state != enums.State.ACTIVE:
            raise exceptions.PermissionDenied(
                "The signing key must be in the Active state to be used for "
                "signature verification."
            )

        masks = managed_object.cryptographic_usage_masks
        if enums.CryptographicUsageMask.VERIFY not in masks:
            raise exceptions.PermissionDenied(
                "The Verify bit must be set in the signing key's "
                "cryptographic usage mask."
            )

        result = self._cryptography_engine.verify_signature(
            signing_key=managed_object.value,
            message=payload.data,
            signature=payload.signature_data,
            padding_method=parameters.padding_method,
            signing_algorithm=parameters.cryptographic_algorithm,
            hashing_algorithm=parameters.hashing_algorithm,
            digital_signature_algorithm=parameters.digital_signature_algorithm
        )

        if result:
            validity = enums.ValidityIndicator.VALID
        else:
            validity = enums.ValidityIndicator.INVALID

        response_payload = payloads.SignatureVerifyResponsePayload(
            unique_identifier=unique_identifier,
            validity_indicator=validity
        )
        return response_payload

    @_kmip_version_supported('1.2')
    def _process_mac(self, payload):
        self._logger.info("Processing operation: MAC")

        unique_identifier = self._id_placeholder
        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier.value

        # TODO: Currently use the GET operation policy here to ensure only a
        # user with read access to the secret can use it to compute a MAC
        # value. However, the MAC operation's access should be controlled by
        # cryptographic usage mask instead of operation policy.
        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET
        )

        algorithm = None
        if (payload.cryptographic_parameters and
                payload.cryptographic_parameters.cryptographic_algorithm):
            algorithm = \
                payload.cryptographic_parameters.cryptographic_algorithm
        elif (isinstance(managed_object, objects.Key) and
              managed_object.cryptographic_algorithm):
            algorithm = managed_object.cryptographic_algorithm
        else:
            raise exceptions.PermissionDenied(
                "The cryptographic algorithm must be specified "
                "for the MAC operation"
            )

        key = None
        if managed_object.value:
            key = managed_object.value
        else:
            raise exceptions.PermissionDenied(
                "A secret key value must be specified "
                "for the MAC operation"
            )

        data = None
        if payload.data:
            data = payload.data.value
        else:
            raise exceptions.PermissionDenied(
                "No data to be MACed"
            )

        if managed_object.state != enums.State.ACTIVE:
            raise exceptions.PermissionDenied(
                "Object is not in a state that can be used for MACing."
            )

        if enums.CryptographicUsageMask.MAC_GENERATE not in \
           managed_object.cryptographic_usage_masks:
                raise exceptions.PermissionDenied(
                    "MAC Generate must be set in the object's cryptographic "
                    "usage mask"
                )

        result = self._cryptography_engine.mac(
            algorithm,
            key,
            data
        )

        response_payload = payloads.MACResponsePayload(
            unique_identifier=attributes.UniqueIdentifier(unique_identifier),
            mac_data=MACData(result)
        )

        return response_payload

    @_kmip_version_supported('1.2')
    def _process_sign(self, payload):
        self._logger.info("Processing operation: Sign")

        unique_identifier = self._id_placeholder
        if payload.unique_identifier:
            unique_identifier = payload.unique_identifier

        managed_object = self._get_object_with_access_controls(
            unique_identifier,
            enums.Operation.GET
        )

        parameters = payload.cryptographic_parameters
        if parameters is None:
            # TODO (dane-fichter): Pull the cryptographic parameters from
            # the managed object with lowest attribute index.
            raise exceptions.InvalidField(
                "The cryptographic parameters must be specified."
            )

        if managed_object._object_type != enums.ObjectType.PRIVATE_KEY:
            raise exceptions.PermissionDenied(
                "The requested signing key is not a private key. A private "
                "key must be specified."
            )

        if managed_object.state != enums.State.ACTIVE:
            raise exceptions.PermissionDenied(
                "The signing key must be in the Active state to be used for "
                "signing."
            )

        masks = managed_object.cryptographic_usage_masks
        if enums.CryptographicUsageMask.SIGN not in masks:
            raise exceptions.PermissionDenied(
                "The Sign bit must be set in the signing key's "
                "cryptographic usage mask."
            )

        result = self._cryptography_engine.sign(
            digital_signature_algorithm=parameters.digital_signature_algorithm,
            crypto_alg=parameters.cryptographic_algorithm,
            hash_algorithm=parameters.hashing_algorithm,
            padding=parameters.padding_method,
            signing_key=managed_object.value,
            data=payload.data
        )

        response_payload = payloads.SignResponsePayload(
            unique_identifier=unique_identifier,
            signature_data=result
        )

        return response_payload
