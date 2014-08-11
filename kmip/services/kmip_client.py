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

from kmip.services.results import CreateResult
from kmip.services.results import GetResult
from kmip.services.results import DestroyResult
from kmip.services.results import RegisterResult

from kmip.core import attributes as attr

from kmip.core.enums import Operation as OperationEnum

from kmip.core import objects
from kmip.core.server import KMIP

from kmip.core.messages.contents import Authentication
from kmip.core.messages.contents import BatchCount
from kmip.core.messages.contents import ProtocolVersion
from kmip.core.messages.contents import Operation

from kmip.core.messages import messages
from kmip.core.messages import operations

from kmip.services.kmip_protocol import KMIPProtocol

from kmip.core.utils import BytearrayStream

from thrift.transport import TSocket
from thrift.transport import TTransport

import logging
import logging.config


class KMIPProxy(KMIP):

    # TODO (peter-hamilton) Move these defaults into config
    def __init__(self, hostname='127.0.0.1', port=5696):
        super(self.__class__, self).__init__()
        self.logger = logging.getLogger(__name__)
        self.socket = TSocket.TSocket(hostname, port)
        self.transport = TTransport.TBufferedTransport(self.socket)
        self.protocol = KMIPProtocol(self.transport)

    def open(self):
        self.transport.open()

    def close(self):
        self.transport.close()

    def create(self, object_type, template_attribute, credential=None):
        object_type = attr.ObjectType(object_type)
        return self._create(object_type=object_type,
                            template_attribute=template_attribute,
                            credential=credential)

    def get(self, uuid=None, key_format_type=None, key_compression_type=None,
            key_wrapping_specification=None, credential=None):
        return self._get(unique_identifier=uuid, credential=credential)

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

    def _create(self,
                object_type=None,
                template_attribute=None,
                credential=None):
        operation = Operation(OperationEnum.CREATE)

        if object_type is None:
            raise ValueError('object_type cannot be None')

        req_pl = operations.CreateRequestPayload(
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
            kft = operations.GetRequestPayload.KeyFormatType(key_format_type)
        if key_compression_type is not None:
            kct = key_compression_type
            kct = operations.GetRequestPayload.KeyCompressionType(kct)
        if key_wrapping_specification is not None:
            kws = objects.KeyWrappingSpecification(key_wrapping_specification)

        req_pl = operations.GetRequestPayload(unique_identifier=uuid,
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

    def _destroy(self,
                 unique_identifier=None,
                 credential=None):
        operation = Operation(OperationEnum.DESTROY)

        uuid = None
        if unique_identifier is not None:
            uuid = attr.UniqueIdentifier(unique_identifier)

        payload = operations.DestroyRequestPayload(unique_identifier=uuid)

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

    def _register(self,
                  object_type=None,
                  template_attribute=None,
                  secret=None,
                  credential=None):
        operation = Operation(OperationEnum.REGISTER)

        if object_type is None:
            raise ValueError('object_type cannot be None')

        req_pl = operations.RegisterRequestPayload(
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

    def _build_request_message(self, credential, batch_items):
        protocol_version = ProtocolVersion.create(1, 1)

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
