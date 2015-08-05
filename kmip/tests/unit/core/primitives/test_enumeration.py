# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import enums
from kmip.core import errors
from kmip.core import primitives
from kmip.core import utils


class TestEnumeration(testtools.TestCase):

    def setUp(self):
        super(TestEnumeration, self).setUp()
        self.stream = utils.BytearrayStream()
        primitives.Enumeration.ENUM_TYPE = enums.Types
        self.bad_type = errors.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.Enumeration.{0}', 'type', '{1}', '{2}')
        self.bad_value = errors.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.Enumeration.{0}', 'value', '{1}', '{2}')
        self.bad_write = errors.ErrorStrings.BAD_EXP_RECV.format(
            'primitives.Enumeration', 'write', '{0} bytes', '{1} bytes')
        self.bad_encoding = errors.ErrorStrings.BAD_ENCODING.format(
            'primitives.Enumeration', 'write')

    def tearDown(self):
        super(TestEnumeration, self).tearDown()

    def test_init(self):
        e = primitives.Enumeration(enums.Types.DEFAULT)

        self.assertIsInstance(e.enum, enums.Types,
                              self.bad_type.format('enum', enums.Types,
                                                   type(e.enum)))
        self.assertEqual(
            enums.Types.DEFAULT, e.enum,
            self.bad_value.format('enum', enums.Types.DEFAULT, e.enum))

        default = enums.Types.DEFAULT
        self.assertEqual(default.value, e.value,
                         self.bad_value.format('value', default.value,
                                               e.value))

    def test_init_unset(self):
        e = primitives.Enumeration()

        self.assertEqual(None, e.enum,
                         self.bad_value.format('enum', None, e.enum))
        self.assertEqual(0, e.value,
                         self.bad_value.format('value', 0, e.value))

    def test_validate_on_valid(self):
        e = primitives.Enumeration()
        e.enum = enums.Types.DEFAULT

        # Check no exception thrown
        e.validate()

    def test_validate_on_valid_unset(self):
        e = primitives.Enumeration()

        # Check no exception thrown
        e.validate()

    def test_validate_on_invalid_type(self):
        e = primitives.Enumeration()
        e.enum = 0

        self.assertRaises(TypeError, e.validate)

    def test_read(self):
        encoding = (
            b'\x42\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        self.stream = utils.BytearrayStream(encoding)
        e = primitives.Enumeration()
        e.read(self.stream)

        self.assertIsInstance(e.enum, enums.Types,
                              self.bad_type.format('enum', enums.Types,
                                                   type(e.enum)))
        self.assertEqual(enums.Types.DEFAULT, e.enum,
                         self.bad_value.format('enum', enums.Types.DEFAULT,
                                               type(e.enum)))
        default = enums.Types.DEFAULT
        self.assertEqual(default.value, e.value,
                         self.bad_value.format('value', default.value,
                                               e.value))

    def test_write(self):
        encoding = (
            b'\x42\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00'
            b'\x00')
        e = primitives.Enumeration(enums.Types.DEFAULT)
        e.write(self.stream)

        result = self.stream.read()
        len_exp = len(encoding)
        len_rcv = len(result)

        self.assertEqual(len_exp, len_rcv, self.bad_write.format(len_exp,
                                                                 len_rcv))
        self.assertEqual(encoding, result, self.bad_encoding)

    def test_write_unsigned(self):
        """
        Test that a large primitives.Enumeration value is written correctly as
        an unsigned integer.
        """
        encoding = (
            b'\x42\x00\x00\x05\x00\x00\x00\x04\x80\x00\x00\x00\x00\x00\x00'
            b'\x00')
        e = primitives.Enumeration(enums.OpaqueDataType.NONE)
        e.write(self.stream)
        result = self.stream.read()

        self.assertEqual(len(encoding), len(result))
        self.assertEqual(encoding, result)
