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

import binascii
import errno
import logging
import socket
import struct
import threading
import time

from cryptography import x509

from kmip.core import enums
from kmip.core import exceptions
from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core import utils

from kmip.services.server import auth

class KmipSession(threading.Thread):
    """
    A session thread representing a single KMIP client/server interaction.
    """

    def __init__(self,
                 engine,
                 connection,
                 address,
                 name=None,
                 enable_tls_client_auth=True,
                 auth_settings=None):
        """
        Create a KmipSession.

        Args:
            engine (KmipEngine): A reference to the central server application
                that handles message processing. Required.
            connection (socket): A client socket.socket TLS connection
                representing a new KMIP connection. Required.
            address (tuple): The address tuple produced with the session
                connection. Contains the IP address and port number of the
                remote connection endpoint. Required.
            name (str): The name of the KmipSession. Optional, defaults to
                None.
            enable_tls_client_auth (bool): A flag that enables a strict check
                for the client auth flag in the extended key usage extension
                in client certificates when establishing the client/server TLS
                connection. Optional, defaults to True.
            auth_settings (list): A list of tuples, each containing (1) the
                name of the 'auth:' settings block from the server config file,
                and (2) a dictionary of configuration settings for a specific
                authentication plugin. Optional, defaults to None.
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
        self._address = address

        self._enable_tls_client_auth = enable_tls_client_auth
        self._auth_settings = [] if auth_settings is None else auth_settings

        self._session_time = time.time()
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

        try:
            self._connection.do_handshake()
        except Exception as e:
            self._logger.info("Failure running TLS handshake")
            self._logger.exception(e)
        else:
            while True:
                try:
                    self._handle_message_loop()
                except exceptions.ConnectionClosed:
                    break
                except Exception as e:
                    self._logger.info("Failure handling message loop")
                    self._logger.exception(e)

        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            if e.errno != errno.ENOTCONN:
                raise
        finally:
            self._connection.close()
        self._logger.info("Stopping session: {0}".format(self.name))

    def _handle_message_loop(self):
        request_data = self._receive_request()
        request = messages.RequestMessage()

        max_size = self._max_response_size
        kmip_version = contents.protocol_version_to_kmip_version(
            self._engine.default_protocol_version
        )

        try:
            if (hasattr(self._connection, 'shared_ciphers')
                    and self._connection.shared_ciphers() is not None):
                shared_ciphers = self._connection.shared_ciphers()
                self._logger.debug(
                    "Possible session ciphers: {0}".format(len(shared_ciphers))
                )
                for cipher in shared_ciphers:
                    self._logger.debug(cipher)
            self._logger.debug(
                "Session cipher selected: {0}".format(
                    self._connection.cipher()
                )
            )

            certificate = auth.get_certificate_from_connection(
                self._connection
            )
            if certificate is None:
                raise exceptions.PermissionDenied(
                    "The client certificate could not be loaded from the "
                    "session connection."
                )

            if self._enable_tls_client_auth:
                extension = auth.get_extended_key_usage_from_certificate(
                    certificate
                )
                if extension is None:
                    raise exceptions.PermissionDenied(
                        "The extended key usage extension is missing from "
                        "the client certificate."
                    )
                if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH not in extension:
                    raise exceptions.PermissionDenied(
                        "The extended key usage extension is not marked for "
                        "client authentication in the client certificate."
                    )

            request.read(request_data, kmip_version=kmip_version)
        except exceptions.PermissionDenied as e:
            self._logger.warning("Failure verifying the client certificate.")
            self._logger.exception(e)
            response = self._engine.build_error_response(
                contents.ProtocolVersion(1, 0),
                enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL,
                "Error verifying the client certificate. "
                "See server logs for more information."
            )
        except Exception as e:
            self._logger.warning("Failure parsing request message.")
            self._logger.exception(e)
            response = self._engine.build_error_response(
                contents.ProtocolVersion(1, 0),
                enums.ResultReason.INVALID_MESSAGE,
                "Error parsing request message. See server logs for more "
                "information."
            )
        else:
            try:
                client_identity = self.authenticate(certificate, request)
                self._logger.info(
                    "Session client identity: {}".format(client_identity[0])
                )
            except Exception:
                self._logger.warning("Authentication failed.")
                response = self._engine.build_error_response(
                    request.request_header.protocol_version,
                    enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL,
                    "An error occurred during client authentication. "
                    "See server logs for more information."
                )
            else:
                try:
                    results = self._engine.process_request(
                        request,
                        client_identity
                    )
                    response, max_response_size, protocol_version = results
                    kmip_version = contents.protocol_version_to_kmip_version(
                        protocol_version
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
                        "An unexpected error occurred while processing "
                        "request."
                    )
                    self._logger.exception(e)
                    response = self._engine.build_error_response(
                        request.request_header.protocol_version,
                        enums.ResultReason.GENERAL_FAILURE,
                        "An unexpected error occurred while processing "
                        "request. See server logs for more information."
                    )

        response_data = utils.BytearrayStream()
        response.write(response_data, kmip_version=kmip_version)

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
            response.write(response_data, kmip_version=kmip_version)

        self._send_response(response_data.buffer)

    def authenticate(self, certificate, request):
        credentials = []
        if request.request_header.authentication is not None:
            credentials = request.request_header.authentication.credentials

        plugin_enabled = False

        for auth_settings in self._auth_settings:
            plugin_name, plugin_config = auth_settings

            if plugin_name.startswith("auth:slugs"):
                if plugin_config.get("enabled") == "True":
                    plugin_enabled = True
                    plugin = auth.SLUGSConnector(plugin_config.get("url"))
                    self._logger.debug(
                        "Authenticating with plugin: {}".format(plugin_name)
                    )
                    try:
                        client_identity = plugin.authenticate(
                            certificate,
                            (self._address, self._session_time),
                            credentials
                        )
                    except Exception as e:
                        self._logger.warning(
                            "Authentication failed."
                        )
                        self._logger.error(e)
                        self._logger.exception(e)
                    else:
                        self._logger.debug(
                            "Authentication succeeded for client identity: "
                            "{}".format(client_identity[0])
                        )
                        return client_identity
            else:
                self._logger.warning(
                    "Authentication plugin '{}' is not "
                    "supported.".format(plugin_name)
                )

        if not plugin_enabled:
            self._logger.debug(
                "No authentication plugins are enabled. The client identity "
                "will be extracted from the client certificate."
            )
            try:
                client_identity = auth.get_client_identity_from_certificate(
                    certificate
                )
            except Exception as e:
                self._logger.warning("Client identity extraction failed.")
                self._logger.exception(e)
            else:
                self._logger.debug(
                    "Extraction succeeded for client identity: {}".format(
                        client_identity
                    )
                )
                return tuple([client_identity, None])

        raise exceptions.PermissionDenied("Authentication failed.")

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
            self._logger.debug(
                "Request encoding: {}".format(binascii.hexlify(message))
            )
            return message

    def _send_response(self, data):
        if len(data) > 0:
            self._logger.debug(
                "Response encoding: {}".format(binascii.hexlify(bytes(data)))
            )
            self._connection.sendall(bytes(data))
