# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
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

import testtools

from kmip.core import utils


class TestBytearrayStreamExtended(testtools.TestCase):
    def test_bytearraystream_init_empty(self):
        stream = utils.BytearrayStream()
        self.assertEqual(b"", stream.buffer)
        self.assertEqual(0, stream.length())
        self.assertEqual(0, len(stream))

    def test_bytearraystream_init_with_data(self):
        data = b"\x00\x01\x02"
        stream = utils.BytearrayStream(data)
        self.assertEqual(data, stream.buffer)
        self.assertEqual(len(data), stream.length())

    def test_bytearraystream_read_write(self):
        stream = utils.BytearrayStream()
        written = stream.write(b"abc")
        self.assertEqual(3, written)
        self.assertEqual(3, stream.length())
        self.assertEqual(b"a", stream.read(1))
        self.assertEqual(2, stream.length())
        self.assertEqual(b"bc", stream.read())
        self.assertEqual(0, stream.length())

    def test_bytearraystream_peek(self):
        stream = utils.BytearrayStream(b"hello")
        self.assertEqual(b"he", stream.peek(2))
        self.assertEqual(5, stream.length())
        self.assertEqual(b"hello", stream.peek())
        self.assertEqual(5, stream.length())

    def test_bytearraystream_length(self):
        stream = utils.BytearrayStream(b"data")
        self.assertEqual(4, stream.length())
        self.assertEqual(4, len(stream))

    def test_bytearraystream_read_past_end(self):
        stream = utils.BytearrayStream(b"xyz")
        self.assertEqual(b"xyz", stream.read(10))
        self.assertEqual(0, stream.length())
        self.assertEqual(b"", stream.read(1))

    def test_bytearraystream_write_large_data(self):
        payload = b"a" * (1024 * 1024)
        stream = utils.BytearrayStream()
        written = stream.write(payload)
        self.assertEqual(len(payload), written)
        self.assertEqual(len(payload), stream.length())
        self.assertEqual(payload[:1024], stream.read(1024))
        self.assertEqual(len(payload) - 1024, stream.length())
