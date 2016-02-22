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

import mock
import testtools
from binascii import unhexlify as hex2bin

from kmip.core.server import KMIPImpl
from kmip.services.server.processor import Processor
from kmip.services.server.kmip_protocol import KMIPProtocolFactory


class TestServerProcessor(testtools.TestCase):
    """
    Integration test suite for the Kmip Server Processor.
    """

    def _setTimeStamp(self, data, ref):
        """
        Take raw TimeStamp data from 'ref' and update with it
        the TimeStamp in 'data'.

        Applied to the data blob sent by processor before comparing it
        with the reference response data.
        """

        time_stamp_pattern = hex2bin('4200920900000008')
        try:
            idx_data = data.index(time_stamp_pattern)
            idx_ref = ref.index(time_stamp_pattern)
        except Exception:
            return data
        data = data[:idx_data] + ref[idx_ref:idx_ref+16] + data[idx_data+16:]
        return data

    def setUp(self):
        super(TestServerProcessor, self).setUp()

    def tearDown(self):
        super(TestServerProcessor, self).tearDown()

    def test_init(self):
        """
        Test that a Kmip Server Processor can be created without errors.
        """

        handler = KMIPImpl()
        Processor(handler)

    def _integration_test_process(self, request, expected):
        """
        Semi-integration test of the Request processing;
         includes the encode/decode of messages and operation specific
         Payloads.

        WF is mocked on the socket level:
         - request blob data are supplied to socket in two chunks:
             -- Request tag/type/length;
             -- Request Message data.
         - data sent by socket are restored from the mock-calls and compared
           with expected data (excluding the TimeStamp data -- TODO).
        """

        socket = mock.MagicMock()
        socket.recv = mock.MagicMock(side_effect=[request[:8], request[8:]])

        socket.sendall = mock.MagicMock()

        factory = KMIPProtocolFactory()
        protocol = factory.getProtocol(socket)

        handler = KMIPImpl()
        processor = Processor(handler)

        processor.process(protocol, protocol)

        (args, kwargs) = socket.sendall.call_args
        to_cmp = self._setTimeStamp(args[0], expected)
        self.assertEqual(expected, to_cmp, "Unexpected error")

    def test_process_discovery_versions(self):
        """
        'DiscoveryVersion':
         - request:
           --  header with protocol version and credential authentication;
           --  batch item 'Operation DiscoverVersions' without parameters
         - expected:
           -- response header with procotol-version, time stamp, batch count
           -- batch item with two versions supported by server
        """
        request = hex2bin(
            '42007801000000b04200770100000088420069010000002042006a02000000040'
            '00000010000000042006b0200000004000000010000000042000c010000004842'
            '00230100000040420024050000000400000001000000004200250100000028420'
            '099070000000a4b6d6970436c69656e740000000000004200a10700000006436f'
            '75636f75000042000d0200000004000000010000000042000f010000001842005'
            'c05000000040000001e000000004200790100000000')
        response = hex2bin(
            '42007b01000000d042007a0100000048420069010000002042006a02000000040'
            '00000010000000042006b02000000040000000100000000420092090000000800'
            '00000056bda8eb42000d0200000004000000010000000042000f0100000078420'
            '05c05000000040000001e0000000042007f050000000400000000000000004200'
            '7c0100000050420069010000002042006a0200000004000000010000000042006'
            'b02000000040000000100000000420069010000002042006a0200000004000000'
            '010000000042006b02000000040000000000000000')

        self._integration_test_process(request, response)

    def test_process_create_symmetric_key(self):
        """
        'Create':
         - request:
           --  header with protocol version and credential authentication;
           --  batch item 'Operation Create':
               -- object type : symmetric key
               -- attributes:
                  -- Cryptographic Algorithm: AES
                  -- Cryptographic Usage Mask
                  -- Cryptographic Length: 128
                  -- Name
         - expected:
           -- response header with procotol-version, time stamp, batch count
           -- batch item with:
             -- operation: Create;
             -- result status: Success;
             -- response payload:
                -- object type: symmetric key;
                -- UID: '1';
                -- attribute template:
                   -- 'Unique Identifier': '1'
        """
        request = hex2bin(
            '42007801000001b04200770100000088420069010000002042006a02000000040'
            '00000010000000042006b0200000004000000010000000042000c010000004842'
            '00230100000040420024050000000400000001000000004200250100000028420'
            '099070000000a4b6d6970436c69656e740000000000004200a10700000006436f'
            '75636f75000042000d0200000004000000010000000042000f010000011842005'
            'c0500000004000000010000000042007901000001004200570500000004000000'
            '020000000042009101000000e8420008010000003042000a07000000174372797'
            '0746f6772617068696320416c676f726974686d0042000b050000000400000003'
            '00000000420008010000003042000a070000001843727970746f6772617068696'
            '3205573616765204d61736b42000b02000000040000000c000000004200080100'
            '00003042000a070000001443727970746f67726170686963204c656e677468000'
            '0000042000b02000000040000008000000000420008010000003842000a070000'
            '00044e616d650000000042000b0100000020420055070000000854657374204b6'
            '57942005405000000040000000100000000')
        response = hex2bin(
            '42007b01000000e042007a0100000048420069010000002042006a02000000040'
            '00000010000000042006b02000000040000000100000000420092090000000800'
            '00000056c488d742000d0200000004000000010000000042000f0100000088420'
            '05c0500000004000000010000000042007f050000000400000000000000004200'
            '7c010000006042005705000000040000000200000000420094070000000131000'
            '000000000004200910100000038420008010000003042000a0700000011556e69'
            '717565204964656e7469666965720000000000000042000b07000000013100000'
            '000000000')

        self._integration_test_process(request, response)
