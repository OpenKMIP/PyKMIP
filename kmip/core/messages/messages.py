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

from kmip.core.enums import Tags

from kmip.core.messages import contents
from kmip.core.messages.contents import AsynchronousCorrelationValue
from kmip.core.messages.contents import BatchErrorContinuationOption

from kmip.core.factories.payloads.request import RequestPayloadFactory
from kmip.core.factories.payloads.response import ResponsePayloadFactory

from kmip.core.primitives import Struct

from kmip.core.utils import BytearrayStream


class RequestHeader(Struct):

    def __init__(self,
                 protocol_version=None,
                 maximum_response_size=None,
                 asynchronous_indicator=None,
                 authentication=None,
                 batch_error_cont_option=None,
                 batch_order_option=None,
                 time_stamp=None,
                 batch_count=None):
        super(RequestHeader, self).__init__(tag=Tags.REQUEST_HEADER)
        self.protocol_version = protocol_version
        self.maximum_response_size = maximum_response_size
        self.asynchronous_indicator = asynchronous_indicator
        self.authentication = authentication
        self.batch_error_cont_option = batch_error_cont_option
        self.batch_order_option = batch_order_option
        self.time_stamp = time_stamp
        self.batch_count = batch_count

    def read(self, istream):
        super(RequestHeader, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.protocol_version = contents.ProtocolVersion()
        self.protocol_version.read(tstream)

        # Read the maximum response size if it is present
        if self.is_tag_next(Tags.MAXIMUM_RESPONSE_SIZE, tstream):
            self.maximum_response_size = contents.MaximumResponseSize()
            self.maximum_response_size.read(tstream)

        # Read the asynchronous indicator if it is present
        if self.is_tag_next(Tags.ASYNCHRONOUS_INDICATOR, tstream):
            self.asynchronous_indicator = contents.AsynchronousIndicator()
            self.asynchronous_indicator.read(tstream)

        # Read the authentication if it is present
        if self.is_tag_next(Tags.AUTHENTICATION, tstream):
            self.authentication = contents.Authentication()
            self.authentication.read(tstream)

        # Read the batch error continuation option if it is present
        if self.is_tag_next(Tags.BATCH_ERROR_CONTINUATION_OPTION, tstream):
            self.batch_error_cont_option = BatchErrorContinuationOption()
            self.batch_error_cont_option.read(tstream)

        # Read the batch order option if it is present
        if self.is_tag_next(Tags.BATCH_ORDER_OPTION, tstream):
            self.batch_order_option = contents.BatchOrderOption()
            self.batch_order_option.read(tstream)

        # Read the time stamp if it is present
        if self.is_tag_next(Tags.TIME_STAMP, tstream):
            self.time_stamp = contents.TimeStamp()
            self.time_stamp.read(tstream)

        self.batch_count = contents.BatchCount()
        self.batch_count.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of a request header to the stream
        self.protocol_version.write(tstream)
        if self.maximum_response_size is not None:
            self.maximum_response_size.write(tstream)
        if self.asynchronous_indicator is not None:
            self.asynchronous_indicator.write(tstream)
        if self.authentication is not None:
            self.authentication.write(tstream)
        if self.batch_error_cont_option is not None:
            self.batch_error_cont_option.write(tstream)
        if self.batch_order_option is not None:
            self.batch_order_option.write(tstream)
        if self.time_stamp is not None:
            self.time_stamp.write(tstream)
        self.batch_count.write(tstream)

        # Write the length and value of the request header
        self.length = tstream.length()
        super(RequestHeader, self).write(ostream)
        ostream.write(tstream.buffer)


class ResponseHeader(Struct):

    def __init__(self,
                 protocol_version=None,
                 time_stamp=None,
                 batch_count=None):
        super(ResponseHeader, self).__init__(tag=Tags.RESPONSE_HEADER)
        self.protocol_version = protocol_version
        self.time_stamp = time_stamp
        self.batch_count = batch_count
        self.validate()

    def read(self, istream):
        super(ResponseHeader, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.protocol_version = contents.ProtocolVersion()
        self.protocol_version.read(tstream)

        self.time_stamp = contents.TimeStamp()
        self.time_stamp.read(tstream)

        self.batch_count = contents.BatchCount()
        self.batch_count.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of a response header to the stream
        self.protocol_version.write(tstream)
        self.time_stamp.write(tstream)
        self.batch_count.write(tstream)

        # Write the length and value of the request header
        self.length = tstream.length()
        super(ResponseHeader, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        if self.protocol_version is not None:
            # TODO (peter-hamilton) conduct type check
            self.protocol_version.validate()
        if self.time_stamp is not None:
            # TODO (peter-hamilton) conduct type check
            self.time_stamp.validate()
        if self.batch_count is not None:
            # TODO (peter-hamilton) conduct type check
            self.batch_count.validate()


class RequestBatchItem(Struct):

    def __init__(self,
                 operation=None,
                 unique_batch_item_id=None,
                 request_payload=None,
                 message_extension=None):
        super(RequestBatchItem, self).__init__(tag=Tags.REQUEST_BATCH_ITEM)

        self.payload_factory = RequestPayloadFactory()

        self.operation = operation
        self.unique_batch_item_id = unique_batch_item_id
        self.request_payload = request_payload
        self.message_extension = message_extension

    def read(self, istream):
        super(RequestBatchItem, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the batch item operation
        self.operation = contents.Operation()
        self.operation.read(tstream)

        # Read the unique batch item ID if it is present
        if self.is_tag_next(Tags.UNIQUE_BATCH_ITEM_ID, tstream):
            self.unique_batch_item_id = contents.UniqueBatchItemID()
            self.unique_batch_item_id.read(tstream)

        # Dynamically create the response payload class that belongs to the
        # operation
        self.request_payload = self.payload_factory.create(
            self.operation.value)
        self.request_payload.read(tstream)

        # Read the message extension if it is present
        if self.is_tag_next(Tags.MESSAGE_EXTENSION, tstream):
            self.message_extension = contents.MessageExtension()
            self.message_extension.read(tstream)

        self.is_oversized(tstream)

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the batch item to the stream
        self.operation.write(tstream)

        if self.unique_batch_item_id is not None:
            self.unique_batch_item_id.write(tstream)

        self.request_payload.write(tstream)

        if self.message_extension is not None:
            self.message_extension.write(tstream)

        # Write the length and value of the batch item
        self.length = tstream.length()
        super(RequestBatchItem, self).write(ostream)
        ostream.write(tstream.buffer)


class ResponseBatchItem(Struct):

    def __init__(self,
                 operation=None,
                 unique_batch_item_id=None,
                 result_status=None,
                 result_reason=None,
                 result_message=None,
                 async_correlation_value=None,
                 response_payload=None,
                 message_extension=None):
        super(ResponseBatchItem, self).__init__(tag=Tags.RESPONSE_BATCH_ITEM)

        self.payload_factory = ResponsePayloadFactory()

        self.operation = operation
        self.unique_batch_item_id = unique_batch_item_id
        self.result_status = result_status
        self.result_reason = result_reason
        self.result_message = result_message
        self.async_correlation_value = async_correlation_value
        self.response_payload = response_payload
        self.message_extension = message_extension
        self.validate()

    def read(self, istream):
        super(ResponseBatchItem, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        # Read the batch item operation if it is present
        if self.is_tag_next(Tags.OPERATION, tstream):
            self.operation = contents.Operation()
            self.operation.read(tstream)

        # Read the unique batch item ID if it is present
        if self.is_tag_next(Tags.UNIQUE_BATCH_ITEM_ID, tstream):
            self.unique_batch_item_id = contents.UniqueBatchItemID()
            self.unique_batch_item_id.read(tstream)

        # Read the batch item result status
        self.result_status = contents.ResultStatus()
        self.result_status.read(tstream)

        # Read the batch item result reason if it is present
        if self.is_tag_next(Tags.RESULT_REASON, tstream):
            self.result_reason = contents.ResultReason()
            self.result_reason.read(tstream)

        # Read the batch item result message if it is present
        if self.is_tag_next(Tags.RESULT_MESSAGE, tstream):
            self.result_message = contents.ResultMessage()
            self.result_message.read(tstream)

        # Read the batch item asynchronous correlation value if it is present
        if self.is_tag_next(Tags.ASYNCHRONOUS_CORRELATION_VALUE, tstream):
            self.async_correlation_value = AsynchronousCorrelationValue()
            self.async_correlation_value.read(tstream)

        if (self.operation is not None):
            # Dynamically create the response payload class that belongs to the
            # operation
            expected = self.payload_factory.create(self.operation.value)
            if self.is_tag_next(expected.tag, tstream):
                self.response_payload = expected
                self.response_payload.read(tstream)

        # Read the message extension if it is present
        if self.is_tag_next(Tags.MESSAGE_EXTENSION, tstream):
            self.message_extension = contents.MessageExtension()
            self.message_extension.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the contents of the batch item to the stream
        if self.operation is not None:
            self.operation.write(tstream)
        if self.unique_batch_item_id is not None:
            self.unique_batch_item_id.write(tstream)

        self.result_status.write(tstream)

        if self.result_reason is not None:
            self.result_reason.write(tstream)
        if self.result_message is not None:
            self.result_message.write(tstream)
        if self.async_correlation_value is not None:
            self.async_correlation_value.write(tstream)
        if self.response_payload is not None:
            self.response_payload.write(tstream)
        if self.message_extension is not None:
            self.message_extension.write(tstream)

        # Write the length and value of the batch item
        self.length = tstream.length()
        super(ResponseBatchItem, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        pass


class RequestMessage(Struct):

    def __init__(self, request_header=None, batch_items=None,):
        super(RequestMessage, self).__init__(tag=Tags.REQUEST_MESSAGE)
        self.request_header = request_header
        self.batch_items = batch_items

    def read(self, istream):
        super(RequestMessage, self).read(istream)

        self.request_header = RequestHeader()
        self.request_header.read(istream)

        self.batch_items = []
        for _ in range(self.request_header.batch_count.value):
            batch_item = RequestBatchItem()
            batch_item.read(istream)
            self.batch_items.append(batch_item)

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the request header and all batch items
        self.request_header.write(tstream)
        for batch_item in self.batch_items:
            batch_item.write(tstream)

        # Write the TTLV encoding of the request message
        self.length = tstream.length()
        super(RequestMessage, self).write(ostream)
        ostream.write(tstream.buffer)


class ResponseMessage(Struct):

    def __init__(self, response_header=None, batch_items=None,):
        super(ResponseMessage, self).__init__(tag=Tags.RESPONSE_MESSAGE)
        self.response_header = response_header
        self.batch_items = batch_items
        self.validate()

    def read(self, istream):
        super(ResponseMessage, self).read(istream)

        self.response_header = ResponseHeader()
        self.response_header.read(istream)

        self.batch_items = []
        for _ in range(self.response_header.batch_count.value):
            batch_item = ResponseBatchItem()
            batch_item.read(istream)
            self.batch_items.append(batch_item)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        # Write the request header and all batch items
        self.response_header.write(tstream)
        for batch_item in self.batch_items:
            batch_item.write(tstream)

        # Write the TTLV encoding of the request message
        self.length = tstream.length()
        super(ResponseMessage, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        pass
