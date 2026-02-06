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

from struct import unpack

import binascii
import logging

from kmip.core.utils import BytearrayStream

class KMIPProtocol(object):
    HEADER_SIZE = 8

    def __init__(self, socket, buffer_size=1024):
        self.socket = socket
        self.logger = logging.getLogger(__name__)
        # DEBUG logging here may expose secrets, so log at INFO by default.
        # However, if consumers know the risks, let them go ahead and override.
        if self.logger.level == logging.NOTSET:
            self.logger.setLevel(logging.INFO)

    def write(self, data):
        if len(data) > 0:
            sbuffer = bytes(data)
            self.logger.debug('KMIPProtocol.write: {0}'.format(
                binascii.hexlify(sbuffer)))
            self.socket.sendall(sbuffer)

    def read(self):
        try:
            header = self._recv_all(self.HEADER_SIZE)
        except RequestLengthMismatch as e:
            if e.received == 0:
                raise EOFError("No data read from socket")
            else:
                raise
        msg_size = unpack('!I', header[4:])[0]

        payload = self._recv_all(msg_size)
        data = BytearrayStream(header + payload)
        self.logger.debug('KMIPProtocol.read: {0}'.format(
            binascii.hexlify(bytes(data.buffer))))
        return data

    def _recv_all(self, total_bytes_to_be_read):
        bytes_read = 0
        total_msg = b''
        while bytes_read < total_bytes_to_be_read:
            msg = self.socket.recv(total_bytes_to_be_read - bytes_read)
            if not msg:
                break
            bytes_read += len(msg)
            total_msg += msg
        if bytes_read != total_bytes_to_be_read:
            msg = "expected {0}, received {1} bytes".format(
                total_bytes_to_be_read, bytes_read)
            raise RequestLengthMismatch(total_bytes_to_be_read, bytes_read)

        return total_msg

class KMIPProtocolFactory(object):

    def getProtocol(self, socket):
        return KMIPProtocol(socket)

class RequestLengthMismatch(Exception):
    """
    This exception raised when the request read from stream has unexpected
    length.
    """
    def __init__(self, expected, received, message="KMIPProtocol read error"):
        super(RequestLengthMismatch, self).__init__(message)
        self.message = message
        self.expected = expected
        self.received = received

    def __str__(self):
        return "{0}: expected {1}, received {2}".format(
                self.message, self.expected, self.received)

    def __repr__(self):
        return self.__str__()
