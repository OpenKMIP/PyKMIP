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

from thrift.protocol.TProtocol import TProtocolBase

import binascii
import logging

from kmip.core.utils import BytearrayStream


class KMIPProtocol(TProtocolBase):
    HEADER_SIZE = 8

    def __init__(self, trans, buffer_size=1024):
        TProtocolBase.__init__(self, trans)
        self.logger = logging.getLogger(__name__)

    def write(self, data):
        if len(data) > 0:
            sbuffer = bytes(data)
            self.logger.debug('buffer: {0}'.format(binascii.hexlify(sbuffer)))
            self.trans.write(sbuffer)
            self.trans.flush()

    def read(self):
        header = self.trans.readAll(self.HEADER_SIZE)
        msg_size = unpack('!I', header[4:])[0]
        payload = self.trans.readAll(msg_size)
        return BytearrayStream(header + payload)


class KMIPProtocolFactory(object):

    def getProtocol(self, trans):
        return KMIPProtocol(trans)
