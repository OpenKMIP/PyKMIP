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
import socket
import struct
import threading

from kmip.core import enums
from kmip.core import exceptions
from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core import utils


class KmipSession(threading.Thread):
    """
    A session thread representing a single KMIP client/server interaction.
    """

    def __init__(self, engine, connection, name=None):
        """
        Create a KmipSession.

        Args:
            engine (KmipEngine): A reference to the central server application
                that handles message processing. Required.
            connection (socket): A client socket.socket TLS connection
                representing a new KMIP connection. Required.
            name (str): The name of the KmipSession. Optional, defaults to
                None.
        """
        super(KmipSession, self).__init__(
            group=None,
            target=None,
            name=name,
            args=(),
            kwargs={}
        )

        self._logger = logging.getLogger(
            'kmip.server.session.{0}'.format(self.name)
        )

        self._engine = engine
        self._connection = connection

        self._max_buffer_size = 4096
        self._max_request_size = 1048576
        self._max_response_size = 1048576

    def run(self):
        """
        The main thread routine executed by invoking thread.start.

        This method manages the new client connection, running a message
        handling loop. Once this method completes, the thread is finished.
        """
        self._logger.info("Starting session: {0}".format(self.name))

        while True:
            try:
                self._handle_message_loop()
            except exceptions.ConnectionClosed as e:
                break
            except Exception as e:
                self._logger.info("Failure handling message loop")
                self._logger.exception(e)

        self._connection.shutdown(socket.SHUT_RDWR)
        self._connection.close()
        self._logger.info("Stopping session: {0}".format(self.name))

    def _handle_message_loop(self):
        request_data = self._receive_request()
        request = messages.RequestMessage()

        max_size = self._max_response_size

        try:
            request.read(request_data)
        except Exception as e:
            self._logger.warning("Failure parsing request message.")
            self._logger.exception(e)
            response = self._engine.build_error_response(
                contents.ProtocolVersion.create(1, 0),
                enums.ResultReason.INVALID_MESSAGE,
                "Error parsing request message. See server logs for more "
                "information."
            )
        else:
            try:
                response, max_response_size = self._engine.process_request(
                    request
                )
                if max_response_size:
                    max_size = max_response_size
            except exceptions.KmipError as e:
                response = self._engine.build_error_response(
                    request.request_header.protocol_version,
                    e.reason,
                    str(e)
                )
            except Exception as e:
                self._logger.warning(
                    "An unexpected error occurred while processing request."
                )
                self._logger.exception(e)
                response = self._engine.build_error_response(
                    request.request_header.protocol_version,
                    enums.ResultReason.GENERAL_FAILURE,
                    "An unexpected error occurred while processing request. "
                    "See server logs for more information."
                )

        response_data = utils.BytearrayStream()
        response.write(response_data)

        if len(response_data) > max_size:
            self._logger.warning(
                "Response message length too large: "
                "{0} bytes, max {1} bytes".format(
                    len(response_data),
                    self._max_response_size
                )
            )
            response = self._engine.build_error_response(
                request.request_header.protocol_version,
                enums.ResultReason.RESPONSE_TOO_LARGE,
                "Response message length too large. See server logs for "
                "more information."
            )
            response_data = utils.BytearrayStream()
            response.write(response_data)

        self._send_response(response_data.buffer)

    def _receive_request(self):
        header = self._receive_bytes(8)
        message_size = struct.unpack('!I', header[4:])[0]

        payload = self._receive_bytes(message_size)
        data = utils.BytearrayStream(header + payload)

        return data

    def _receive_bytes(self, message_size):
        bytes_received = 0
        message = b''

        while bytes_received < message_size:
            partial_message = self._connection.recv(
                min(message_size - bytes_received, self._max_buffer_size)
            )

            if partial_message is None:
                break
            elif len(partial_message) == 0:
                raise exceptions.ConnectionClosed()
            else:
                bytes_received += len(partial_message)
                message += partial_message

        if bytes_received != message_size:
            raise ValueError(
                "Invalid KMIP message received. Actual message length "
                "does not match the advertised header length."
            )
        else:
            return message

    def _send_response(self, data):
        if len(data) > 0:
            self._connection.sendall(bytes(data))
