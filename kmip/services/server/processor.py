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

import logging
import time

from kmip.core.messages.messages import RequestMessage
from kmip.core.messages.messages import ResponseMessage
from kmip.core.messages.messages import ResponseBatchItem
from kmip.core.messages.messages import ResponseHeader

from kmip.core.messages.contents import AsynchronousIndicator
from kmip.core.messages.contents import BatchErrorContinuationOption
from kmip.core.messages.contents import BatchCount
from kmip.core.messages.contents import TimeStamp

from kmip.core.primitives import Base

from kmip.core.messages.payloads.create import CreateResponsePayload
from kmip.core.messages.payloads.get import GetResponsePayload
from kmip.core.messages.payloads.destroy import DestroyResponsePayload
from kmip.core.messages.payloads.register import RegisterResponsePayload
from kmip.core.messages.payloads.locate import LocateResponsePayload
from kmip.core.messages.payloads.discover_versions import \
    DiscoverVersionsResponsePayload

from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus as RS
from kmip.core.enums import Tags
from kmip.core.enums import BatchErrorContinuationOption as BECO

from kmip.core.utils import BytearrayStream


class Processor(object):
    def __init__(self, handler):
        self.logger = logging.getLogger(__name__)
        self._handler = handler

    def process(self, istream, ostream):
        stream = istream.read()

        if Base.is_tag_next(Tags.REQUEST_MESSAGE, stream):
            message = RequestMessage()
            message.read(stream)
            try:
                result = self._process_request(message)
            except Exception as e:
                raise e
            tstream = BytearrayStream()
            result.write(tstream)
            ostream.write(tstream.buffer)
        elif Base.is_tag_next(Tags.RESPONSE_MESSAGE, stream):
            message = ResponseMessage()
            message.read(stream)
            self._process_response(message)
        else:
            raise ValueError('Processing error: stream contains unknown '
                             'message type')

    def _process_request(self, message):
        header = message.request_header

        protocol_version = header.protocol_version
#        maximum_response_size = header.maximum_response_size
        asynchronous_indicator = header.asynchronous_indicator
#        authentication = header.authentication
        batch_error_cont_option = header.batch_error_cont_option
#        batch_order_option = header.batch_order_option
#        time_stamp = header.time_stamp
        request_batch_count = header.batch_count.value

        # TODO (peter-hamilton) Log receipt of message with time stamp

        if asynchronous_indicator is None:
            asynchronous_indicator = AsynchronousIndicator(False)

        if batch_error_cont_option is None:
            batch_error_cont_option = BatchErrorContinuationOption(BECO.STOP)

        request_batch_items = message.batch_items
        response_batch_items = []

        for i in range(request_batch_count):
            request_batch_item = request_batch_items[i]
            failure_occurred = False

            operation = request_batch_item.operation
            ubi_id = request_batch_item.unique_batch_item_id
            payload = request_batch_item.request_payload
            message_extension = request_batch_item.message_extension

            result = self._process_operation(operation, payload)

            result_status = result[0]
            result_reason = result[1]
            result_message = result[2]
            asyn_cv = None
            response_payload = None
            message_extension = None

            if result_status.value is RS.SUCCESS:
                response_payload = result[3]
            elif result_status.value is RS.OPERATION_FAILED:
                failure_occurred = True
                result_reason = result[1]
            elif result_status.value is RS.OPERATION_PENDING:
                # TODO (peter-hamilton) Need to add a way to track async
                # TODO (peter-hamilton) operations.
                asyn_cv = b'\x00'
            elif result_status.value is RS.OPERATION_UNDONE:
                result_reason = result[1]
            else:
                msg = 'Unrecognized operation result status: {0}'
                raise RuntimeError(msg.format(result_status))

            resp_bi = ResponseBatchItem(operation=operation,
                                        unique_batch_item_id=ubi_id,
                                        result_status=result_status,
                                        result_reason=result_reason,
                                        result_message=result_message,
                                        async_correlation_value=asyn_cv,
                                        response_payload=response_payload,
                                        message_extension=message_extension)
            response_batch_items.append(resp_bi)

            if failure_occurred:
                if batch_error_cont_option.value is BECO.STOP:
                    break
                elif batch_error_cont_option.value is BECO.UNDO:
                    # TODO (peter-hamilton) Tell client to undo operations.
                    # TODO (peter-hamilton) Unclear what response should be.
                    break
                elif batch_error_cont_option.value is BECO.CONTINUE:
                    continue
                else:
                    msg = 'Unrecognized batch error continuation option: {0}'
                    raise RuntimeError(msg.format(batch_error_cont_option))

        response_batch_count = BatchCount(len(response_batch_items))
        response_time_stamp = TimeStamp(int(time.time()))
        response_header = ResponseHeader(protocol_version=protocol_version,
                                         time_stamp=response_time_stamp,
                                         batch_count=response_batch_count)

        response_message = ResponseMessage(response_header=response_header,
                                           batch_items=response_batch_items)
        return response_message

    def _process_response(self, message):
        raise NotImplementedError()

    def _process_operation(self, operation, payload):
        op = operation.value

        if op is Operation.CREATE:
            return self._process_create_request(payload)
        elif op is Operation.GET:
            return self._process_get_request(payload)
        elif op is Operation.DESTROY:
            return self._process_destroy_request(payload)
        elif op is Operation.REGISTER:
            return self._process_register_request(payload)
        elif op is Operation.LOCATE:
            return self._process_locate_request(payload)
        elif op is Operation.DISCOVER_VERSIONS:
            return self._process_discover_versions_request(payload)
        else:
            self.logger.debug("Process operation: Not implemented")
            raise NotImplementedError()

    def _process_create_request(self, payload):
        object_type = payload.object_type
        template_attribute = payload.template_attribute
        result = self._handler.create(object_type, template_attribute)

        result_status = result.result_status
        result_reason = result.result_reason
        result_message = result.result_message
        created_type = result.object_type
        uuid = result.uuid
        template_attribute = result.template_attribute

        resp_pl = CreateResponsePayload(object_type=created_type,
                                        unique_identifier=uuid,
                                        template_attribute=template_attribute)

        return (result_status, result_reason, result_message, resp_pl)

    def _process_get_request(self, payload):
        uuid = None
        kft = None
        kct = None

        unique_identifier = payload.unique_identifier
        key_format_type = payload.key_format_type
        key_compression_type = payload.key_compression_type
        key_wrapping_specification = payload.key_wrapping_specification

        if unique_identifier is not None:
            uuid = unique_identifier
        if key_format_type is not None:
            kft = key_format_type
        if key_compression_type is not None:
            kct = key_compression_type

        result = self._handler.get(uuid, kft, kct,
                                   key_wrapping_specification)

        result_status = result.result_status
        result_reason = result.result_reason
        result_message = result.result_message
        retrieved_type = result.object_type
        uuid = result.uuid
        secret = result.secret

        resp_pl = GetResponsePayload(object_type=retrieved_type,
                                     unique_identifier=uuid,
                                     secret=secret)

        return (result_status, result_reason, result_message, resp_pl)

    def _process_destroy_request(self, payload):
        uuid = payload.unique_identifier
        result = self._handler.destroy(uuid)

        result_status = result.result_status
        result_reason = result.result_reason
        result_message = result.result_message
        uuid = result.uuid

        payload = DestroyResponsePayload(unique_identifier=uuid)

        return (result_status, result_reason, result_message, payload)

    def _process_register_request(self, payload):
        object_type = payload.object_type
        template_attribute = payload.template_attribute
        secret = payload.secret
        result = self._handler.register(object_type, template_attribute,
                                        secret)

        result_status = result.result_status
        result_reason = result.result_reason
        result_message = result.result_message
        uuid = result.uuid
        template_attr = result.template_attribute

        resp_pl = RegisterResponsePayload(unique_identifier=uuid,
                                          template_attribute=template_attr)

        return (result_status, result_reason, result_message, resp_pl)

    def _process_locate_request(self, payload):
        max_items = payload.maximum_items
        storage_mask = payload.storage_status_mask
        objgrp_member = payload.object_group_member
        attributes = payload.attributes

        result = self._handler.locate(max_items, storage_mask,
                                      objgrp_member, attributes)

        result_status = result.result_status
        result_reason = result.result_reason
        result_message = result.result_message

        uuids = result.uuids

        resp_pl = LocateResponsePayload(unique_identifiers=uuids)

        return (result_status, result_reason, result_message, resp_pl)

    def _process_discover_versions_request(self, payload):
        protocol_versions = payload.protocol_versions

        result = self._handler.discover_versions(
                protocol_versions=protocol_versions)

        result_status = result.result_status
        result_reason = result.result_reason
        result_protocol_versions = result.protocol_versions
        result_message = result.result_message

        resp_pl = DiscoverVersionsResponsePayload(
                protocol_versions=result_protocol_versions)

        return (result_status, result_reason, result_message, resp_pl)
