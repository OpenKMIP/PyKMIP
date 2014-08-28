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

import os
import socket
import ssl

from kmip.core.server import KMIPImpl

from kmip.services.kmip_protocol import KMIPProtocolFactory
from kmip.services.processor import Processor

FILE_PATH = os.path.dirname(os.path.abspath(__file__))


class KMIPServer(object):
    def __init__(self, host='127.0.0.1', port=5696,
                 cert_file=None, key_file=None):
        handler = KMIPImpl()
        self._processor = Processor(handler)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, int(port)))
        self.cert_file = cert_file
        self.key_file = key_file

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def serve(self):
        self.socket.listen(0)
        while True:
            connection, address = self.socket.accept()
            if self.cert_file and self.key_file:
                connection = ssl.wrap_socket(connection,
                                             server_side=True,
                                             certfile=self.cert_file,
                                             keyfile=self.key_file)

            factory = KMIPProtocolFactory()
            protocol = factory.getProtocol(connection)
            try:
                while True:
                    self._processor.process(protocol, protocol)
            except Exception:
                connection.close()
