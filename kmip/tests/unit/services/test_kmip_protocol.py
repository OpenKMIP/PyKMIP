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

from mock import call, MagicMock
from testtools import TestCase

import binascii

from kmip.services.kmip_protocol import KMIPProtocol
from kmip.services.kmip_protocol import RequestLengthMismatch
from kmip.services.kmip_protocol import KMIPProtocolFactory

class TestKMIPProtocol(TestCase):

    request = binascii.unhexlify(
            '42007801000000b04200770100000088420069010000002042006a02000000040'
            '00000010000000042006b0200000004000000010000000042000c010000004842'
            '00230100000040420024050000000400000001000000004200250100000028420'
            '099070000000a4b6d6970436c69656e740000000000004200a10700000006436f'
            '75636f75000042000d0200000004000000010000000042000f010000001842005'
            'c05000000040000001e000000004200790100000000')
    response = binascii.unhexlify(
            '42007b01000000d042007a0100000048420069010000002042006a02000000040'
            '00000010000000042006b02000000040000000100000000420092090000000800'
            '00000056bda8eb42000d0200000004000000010000000042000f0100000078420'
            '05c05000000040000001e0000000042007f050000000400000000000000004200'
            '7c0100000050420069010000002042006a0200000004000000010000000042006'
            'b02000000040000000100000000420069010000002042006a0200000004000000'
            '010000000042006b02000000040000000000000000')

    def setUp(self):
        super(TestKMIPProtocol, self).setUp()
        self.factory = KMIPProtocolFactory()

    def tearDown(self):
        super(TestKMIPProtocol, self).tearDown()

    def test_init(self):
        """
        Test that a KmipProtocol can be created without errors.
        """
        socket = MagicMock()
        KMIPProtocol(socket)

    def test_protocol_factory(self):
        mock_name = 'test_protocol_factory'
        socket = MagicMock(mock_name=mock_name)
        protocol = self.factory.getProtocol(socket)

        base = "expected {0}, received {1}"
        msg = base.format(KMIPProtocol, protocol)
        self.assertIsInstance(protocol, KMIPProtocol, msg)
        self.assertEqual(protocol.socket.mock_name, mock_name, msg)

    def test_IO_write(self):
        socket = MagicMock()
        protocol = self.factory.getProtocol(socket)
        protocol.logger = MagicMock()
        protocol.write(self.request)

        protocol.logger.debug.assert_any_call(
            "KMIPProtocol.write: {0}".format(binascii.hexlify(self.request)))
        protocol.socket.sendall.assert_called_once_with(self.request)

    def test_IO_read(self):
        socket = MagicMock()
        socket.recv = MagicMock(
            side_effect=[self.response[:8], self.response[8:]])
        protocol = self.factory.getProtocol(socket)

        received = protocol.read()

        socket.recv.assert_any_call(8)
        socket.recv.assert_any_call(len(self.response) - 8)

        self.assertEqual(self.response, received.peek())

    def test_IO_read_EOF(self):
        socket = MagicMock()
        socket.recv = MagicMock(side_effect=[[]])
        protocol = self.factory.getProtocol(socket)

        try:
            protocol.read()
        except Exception as e:
            self.assertIsInstance(e, EOFError, "Invalid exception")
        else:
            self.assertTrue(False, "Unexpected error")

        socket.recv.assert_any_call(8)

    def test_IO_read_request_length_mismatch(self):
        socket = MagicMock()
        socket.recv = MagicMock(
            side_effect=[self.response[:8], self.response[8:16], []])
        protocol = self.factory.getProtocol(socket)
        resp_len = len(self.response)

        try:
            protocol.read()
        except Exception as e:
            self.assertIsInstance(
                e, RequestLengthMismatch, "Invalid exception")
            self.assertEqual(e.expected, resp_len - 8, "Unexpected expected")
            self.assertEqual(e.received, 8, "Unexpected received")
            self.assertEqual(
                "{0}".format(e),
                "{0}: expected {1}, received {2}".format(
                    "KMIPProtocol read error", resp_len - 8, 8),
                "Invalid RequestLengthMismatch attributes")
        else:
            self.assertTrue(False, "Unexpected error")

        calls = [call(8), call(resp_len - 8), call(resp_len - 16)]
        socket.recv.assert_has_calls(calls)
