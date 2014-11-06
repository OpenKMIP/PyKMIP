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
from kmip.services.results import LocateResult

from kmip.core import attributes as attr

from kmip.core.enums import Operation as OperationEnum
from kmip.core.enums import CredentialType

from kmip.core.factories.credentials import CredentialFactory

from kmip.core import objects
from kmip.core.server import KMIP

from kmip.core.messages.contents import Authentication
from kmip.core.messages.contents import BatchCount
from kmip.core.messages.contents import ProtocolVersion
from kmip.core.messages.contents import Operation

from kmip.core.messages import messages

from kmip.core.messages.payloads import create
from kmip.core.messages.payloads import get
from kmip.core.messages.payloads import register
from kmip.core.messages.payloads import locate
from kmip.core.messages.payloads import destroy

from kmip.services.kmip_protocol import KMIPProtocol

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

    def __init__(self, host=None, port=None, keyfile=None, certfile=None,
                 cert_reqs=None, ssl_version=None, ca_certs=None,
                 do_handshake_on_connect=None,
                 suppress_ragged_eofs=None,
                 username=None,
                 password=None):
        super(self.__class__, self).__init__()
        self.logger = logging.getLogger(__name__)
        self.credential_factory = CredentialFactory()

        self._set_variables(host, port, keyfile, certfile,
                            cert_reqs, ssl_version, ca_certs,
                            do_handshake_on_connect, suppress_ragged_eofs,
                            username, password)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket = ssl.wrap_socket(
            sock,
            keyfile=self.keyfile,
            certfile=self.certfile,
            cert_reqs=self.cert_reqs,
            ssl_version=self.ssl_version,
            ca_certs=self.ca_certs,
            do_handshake_on_connect=self.do_handshake_on_connect,
            suppress_ragged_eofs=self.suppress_ragged_eofs)
        self.protocol = KMIPProtocol(self.socket)

    def open(self):
        self.socket.connect((self.host, self.port))

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)

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

    def locate(self, maximum_items=None, storage_status_mask=None,
               object_group_member=None, attributes=None, credential=None):
        return self._locate(maximum_items=maximum_items,
                            storage_status_mask=storage_status_mask,
                            object_group_member=object_group_member,
                            attributes=attributes, credential=credential)

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
            kft = get.GetRequestPayload.KeyFormatType(key_format_type)
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
        protocol_version = ProtocolVersion.create(1, 1)

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

    def _set_variables(self, host, port, keyfile, certfile,
                       cert_reqs, ssl_version, ca_certs,
                       do_handshake_on_connect, suppress_ragged_eofs,
                       username, password):
        conf = ConfigHelper()

        self.host = conf.get_valid_value(
            host, 'client', 'host', conf.DEFAULT_HOST)

        self.port = int(conf.get_valid_value(
            port, 'client', 'port', conf.DEFAULT_PORT))

        self.keyfile = conf.get_valid_value(
            keyfile, 'client', 'keyfile', None)

        self.certfile = conf.get_valid_value(
            certfile, 'client', 'certfile', None)

        self.cert_reqs = getattr(ssl, conf.get_valid_value(
            cert_reqs, 'client', 'cert_reqs', 'CERT_REQUIRED'))

        self.ssl_version = getattr(ssl, conf.get_valid_value(
            ssl_version, 'client', 'ssl_version', conf.DEFAULT_SSL_VERSION))

        self.ca_certs = conf.get_valid_value(
            ca_certs, 'client', 'ca_certs', conf.DEFAULT_CA_CERTS)

        if conf.get_valid_value(
                do_handshake_on_connect, 'client',
                'do_handshake_on_connect', 'True') == 'True':
            self.do_handshake_on_connect = True
        else:
            self.do_handshake_on_connect = False

        if conf.get_valid_value(
                suppress_ragged_eofs, 'client',
                'suppress_ragged_eofs', 'True') == 'True':
            self.suppress_ragged_eofs = True
        else:
            self.suppress_ragged_eofs = False

        self.username = conf.get_valid_value(
            username, 'client', 'username', conf.DEFAULT_USERNAME)

        self.password = conf.get_valid_value(
            password, 'client', 'password', conf.DEFAULT_PASSWORD)
