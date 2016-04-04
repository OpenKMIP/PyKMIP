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
import os
import socket
import ssl
import warnings

from kmip.core.config_helper import ConfigHelper
from kmip.core.server import KMIPImpl

from kmip.services.server.kmip_protocol import KMIPProtocolFactory
from kmip.services.server.processor import Processor

FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class KMIPServer(object):

    def __init__(self, host=None, port=None, keyfile=None, certfile=None,
                 cert_reqs=None, ssl_version=None, ca_certs=None,
                 do_handshake_on_connect=None, suppress_ragged_eofs=None):
        warnings.simplefilter("always")
        warnings.warn((
            "Please use the newer KmipServer located in kmip.services.server. "
            "This version of the server will be deprecated in the future."),
            PendingDeprecationWarning
        )
        warnings.simplefilter("default")

        self.logger = logging.getLogger(__name__)

        self._set_variables(host, port, keyfile, certfile, cert_reqs,
                            ssl_version, ca_certs, do_handshake_on_connect,
                            suppress_ragged_eofs)

        handler = KMIPImpl()
        self._processor = Processor(handler)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def serve(self):
        self.socket.listen(0)
        while True:
            connection, address = self.socket.accept()
            self.logger.info("Connected by {0}".format(address))
            connection = ssl.wrap_socket(
                connection,
                keyfile=self.keyfile,
                certfile=self.certfile,
                server_side=True,
                cert_reqs=self.cert_reqs,
                ssl_version=self.ssl_version,
                ca_certs=self.ca_certs,
                do_handshake_on_connect=self.do_handshake_on_connect,
                suppress_ragged_eofs=self.suppress_ragged_eofs)

            factory = KMIPProtocolFactory()
            protocol = factory.getProtocol(connection)

            try:
                while True:
                    self._processor.process(protocol, protocol)
            except EOFError as e:
                self.logger.warning("KMIPServer {0} {1}".format(type(e), e))
            except Exception as e:
                self.logger.error('KMIPServer {0} {1}'.format(type(e), e))
            finally:
                connection.close()
                self.logger.info('Connection closed')

    def _set_variables(self, host, port, keyfile, certfile, cert_reqs,
                       ssl_version, ca_certs, do_handshake_on_connect,
                       suppress_ragged_eofs):
        conf = ConfigHelper()
        self.host = conf.get_valid_value(host, 'server',
                                         'host', conf.DEFAULT_HOST)
        self.port = int(conf.get_valid_value(port, 'server',
                                             'port', conf.DEFAULT_PORT))
        self.keyfile = conf.get_valid_value(
            keyfile, 'server', 'keyfile', conf.DEFAULT_KEYFILE)

        self.certfile = conf.get_valid_value(
            certfile, 'server', 'certfile', conf.DEFAULT_CERTFILE)

        self.cert_reqs = getattr(ssl, conf.get_valid_value(
            cert_reqs, 'server', 'cert_reqs', 'CERT_NONE'))

        self.ssl_version = getattr(ssl, conf.get_valid_value(
            ssl_version, 'server', 'ssl_version', conf.DEFAULT_SSL_VERSION))

        self.ca_certs = conf.get_valid_value(
            ca_certs, 'server', 'ca_certs', None)

        if conf.get_valid_value(
                do_handshake_on_connect, 'server',
                'do_handshake_on_connect', 'True') == 'True':
            self.do_handshake_on_connect = True
        else:
            self.do_handshake_on_connect = False

        if conf.get_valid_value(
                suppress_ragged_eofs, 'server',
                'suppress_ragged_eofs', 'True') == 'True':
            self.suppress_ragged_eofs = True
        else:
            self.suppress_ragged_eofs = False
