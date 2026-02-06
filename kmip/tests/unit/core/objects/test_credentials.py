# Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
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

import enum
import mock
import testtools

from kmip import enums
from kmip.core import objects
from kmip.core import utils

class TestNonce(testtools.TestCase):
    """
    Test suite for the Nonce struct.
    """

    def setUp(self):
        super(TestNonce, self).setUp()

        # There are no Nonce encodings available in any of the KMIP testing
        # documents. The following encodings were adapted from other structure
        # encodings present in the KMIP testing suite.
        #
        # This encoding matches the following set of values:
        # Nonce
        #     Nonce ID - 1
        #     Nonce Value - 0x0001020304050607
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\xC8\x01\x00\x00\x00\x20'
            b'\x42\x00\xC9\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xCA\x08\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07'
        )
        self.encoding_missing_nonce_id = utils.BytearrayStream(
            b'\x42\x00\xC8\x01\x00\x00\x00\x10'
            b'\x42\x00\xCA\x08\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07'
        )
        self.encoding_missing_nonce_value = utils.BytearrayStream(
            b'\x42\x00\xC8\x01\x00\x00\x00\x10'
            b'\x42\x00\xC9\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestNonce, self).tearDown()

    def test_init(self):
        """
        Test that a Nonce struct can be constructed without arguments.
        """
        nonce = objects.Nonce()

        self.assertEqual(None, nonce.nonce_id)
        self.assertEqual(None, nonce.nonce_value)

    def test_init_with_args(self):
        """
        Test that a Nonce struct can be constructed with arguments.
        """
        nonce = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )

        self.assertEqual(b'\x01', nonce.nonce_id)
        self.assertEqual(
            b'\x00\x01\x02\x03\x04\x05\x06\x07',
            nonce.nonce_value
        )

    def test_invalid_nonce_id(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the nonce ID of a Nonce struct.
        """
        kwargs = {'nonce_id': 0}
        self.assertRaisesRegex(
            TypeError,
            "Nonce ID must be bytes.",
            objects.Nonce,
            **kwargs
        )

        nonce = objects.Nonce()
        args = (nonce, "nonce_id", 0)
        self.assertRaisesRegex(
            TypeError,
            "Nonce ID must be bytes.",
            setattr,
            *args
        )

    def test_invalid_nonce_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the nonce value of a Nonce struct.
        """
        kwargs = {'nonce_value': 0}
        self.assertRaisesRegex(
            TypeError,
            "Nonce value must be bytes.",
            objects.Nonce,
            **kwargs
        )

        nonce = objects.Nonce()
        args = (nonce, "nonce_value", 0)
        self.assertRaisesRegex(
            TypeError,
            "Nonce value must be bytes.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Nonce struct can be read from a data stream.
        """
        nonce = objects.Nonce()

        self.assertEqual(None, nonce.nonce_id)
        self.assertEqual(None, nonce.nonce_value)

        nonce.read(self.full_encoding)

        self.assertEqual(b'\x01', nonce.nonce_id)
        self.assertEqual(
            b'\x00\x01\x02\x03\x04\x05\x06\x07',
            nonce.nonce_value
        )

    def test_read_missing_nonce_id(self):
        """
        Test that a ValueError gets raised when attempting to read a
        Nonce struct from a data stream missing the nonce ID data.
        """
        nonce = objects.Nonce()

        self.assertEqual(None, nonce.nonce_id)
        self.assertEqual(None, nonce.nonce_value)

        args = (self.encoding_missing_nonce_id, )
        self.assertRaisesRegex(
            ValueError,
            "Nonce encoding missing the nonce ID.",
            nonce.read,
            *args
        )

    def test_read_missing_nonce_value(self):
        """
        Test that a ValueError gets raised when attempting to read a
        Nonce struct from a data stream missing the nonce value data.
        """
        nonce = objects.Nonce()

        self.assertEqual(None, nonce.nonce_id)
        self.assertEqual(None, nonce.nonce_value)

        args = (self.encoding_missing_nonce_value, )
        self.assertRaisesRegex(
            ValueError,
            "Nonce encoding missing the nonce value.",
            nonce.read,
            *args
        )

    def test_write(self):
        """
        Test that a Nonce struct can be written to a data stream.
        """
        nonce = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )
        stream = utils.BytearrayStream()

        nonce.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_nonce_id(self):
        """
        Test that a ValueError gets raised when attempting to write a
        Nonce struct missing nonce ID data to a data stream.
        """
        nonce = objects.Nonce(
            nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Nonce struct is missing the nonce ID.",
            nonce.write,
            *args
        )

    def test_write_missing_nonce_value(self):
        """
        Test that a ValueError gets raised when attempting to write a
        Nonce struct missing nonce value data to a data stream.
        """
        nonce = objects.Nonce(
            nonce_id=b'\x01'
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Nonce struct is missing the nonce value.",
            nonce.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Nonce structs with the same data.
        """
        a = objects.Nonce()
        b = objects.Nonce()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )
        b = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_nonce_id(self):
        """
        Test that the equality operator returns False when comparing two
        Nonce structs with different nonce IDs.
        """
        a = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )
        b = objects.Nonce(
            nonce_id=b'\x02',
            nonce_value=b'\x00\x01\x02\x03'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_nonce_value(self):
        """
        Test that the equality operator returns False when comparing two
        Nonce structs with different nonce values.
        """
        a = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )
        b = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x03\x02\x01\x00'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Nonce structs with different types.
        """
        a = objects.Nonce()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Nonce structs with the same data.
        """
        a = objects.Nonce()
        b = objects.Nonce()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )
        b = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_nonce_id(self):
        """
        Test that the inequality operator returns True when comparing two
        Nonce structs with different nonce IDs.
        """
        a = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )
        b = objects.Nonce(
            nonce_id=b'\x02',
            nonce_value=b'\x00\x01\x02\x03'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_nonce_value(self):
        """
        Test that the inequality operator returns True when comparing two
        Nonce structs with different nonce values.
        """
        a = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03'
        )
        b = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x03\x02\x01\x00'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Nonce structs with different types.
        """
        a = objects.Nonce()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Nonce struct.
        """
        credential = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )
        expected = (
            "Nonce("
            "nonce_id=" + str(b'\x01') + ", "
            "nonce_value=" + str(b'\x00\x01\x02\x03\x04\x05\x06\x07') + ")"
        )
        observed = repr(credential)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Nonce struct.
        """
        credential = objects.Nonce(
            nonce_id=b'\x01',
            nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
        )
        expected = ", ".join([
            "'nonce_id': {}".format(b'\x01'),
            "'nonce_value': {}".format(b'\x00\x01\x02\x03\x04\x05\x06\x07')
        ])
        expected = "{" + expected + "}"
        observed = str(credential)

        self.assertEqual(expected, observed)

class TestUsernamePasswordCredential(testtools.TestCase):
    """
    Test suite for the UsernamePasswordCredential struct.
    """

    def setUp(self):
        super(TestUsernamePasswordCredential, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 11.1.
        #
        # This encoding matches the following set of values:
        # UsernamePasswordCredential
        #     Username - Fred
        #     Password - password1
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x28'
            b'\x42\x00\x99\x07\x00\x00\x00\x04'
            b'\x46\x72\x65\x64\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x09'
            b'\x70\x61\x73\x73\x77\x6F\x72\x64\x31\x00\x00\x00\x00\x00\x00\x00'
        )

        self.encoding_missing_username = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x18'
            b'\x42\x00\xA1\x07\x00\x00\x00\x09'
            b'\x70\x61\x73\x73\x77\x6F\x72\x64\x31\x00\x00\x00\x00\x00\x00\x00'
        )

        self.encoding_missing_password = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x10'
            b'\x42\x00\x99\x07\x00\x00\x00\x04'
            b'\x46\x72\x65\x64\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestUsernamePasswordCredential, self).tearDown()

    def test_init(self):
        """
        Test that a UsernamePasswordCredential struct can be constructed
        without arguments.
        """
        credential = objects.UsernamePasswordCredential()

        self.assertEqual(None, credential.username)
        self.assertEqual(None, credential.password)

    def test_init_with_args(self):
        """
        Test that a UsernamePasswordCredential struct can be constructed with
        arguments.
        """
        credential = objects.UsernamePasswordCredential(
            username="John",
            password="abc123"
        )

        self.assertEqual("John", credential.username)
        self.assertEqual("abc123", credential.password)

    def test_invalid_username(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the username of a UsernamePasswordCredential struct.
        """
        kwargs = {'username': 0}
        self.assertRaisesRegex(
            TypeError,
            "Username must be a string.",
            objects.UsernamePasswordCredential,
            **kwargs
        )

        credential = objects.UsernamePasswordCredential()
        args = (credential, "username", 0)
        self.assertRaisesRegex(
            TypeError,
            "Username must be a string.",
            setattr,
            *args
        )

    def test_invalid_password(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the password of a UsernamePasswordCredential struct.
        """
        kwargs = {'password': 0}
        self.assertRaisesRegex(
            TypeError,
            "Password must be a string.",
            objects.UsernamePasswordCredential,
            **kwargs
        )

        credential = objects.UsernamePasswordCredential()
        args = (credential, "password", 0)
        self.assertRaisesRegex(
            TypeError,
            "Password must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a UsernamePasswordCredential struct can be read from a data
        stream.
        """
        credential = objects.UsernamePasswordCredential()

        self.assertEqual(None, credential.username)
        self.assertEqual(None, credential.password)

        credential.read(self.full_encoding)

        self.assertEqual("Fred", credential.username)
        self.assertEqual("password1", credential.password)

    def test_read_missing_username(self):
        """
        Test that a ValueError gets raised when attempting to read a
        UsernamePasswordCredential struct from a data stream missing the
        username data.
        """
        credential = objects.UsernamePasswordCredential()

        self.assertEqual(None, credential.username)
        self.assertEqual(None, credential.password)

        args = (self.encoding_missing_username, )
        self.assertRaisesRegex(
            ValueError,
            "Username/password credential encoding missing the username.",
            credential.read,
            *args
        )

    def test_read_missing_password(self):
        """
        Test that a UsernamePasswordCredential struct can be read from a data
        stream missing the password data.
        """
        credential = objects.UsernamePasswordCredential()

        self.assertEqual(None, credential.username)
        self.assertEqual(None, credential.password)

        credential.read(self.encoding_missing_password)

        self.assertEqual("Fred", credential.username)
        self.assertEqual(None, credential.password)

    def test_write(self):
        """
        Test that a UsernamePasswordCredential struct can be written to a
        data stream.
        """
        credential = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_username(self):
        """
        Test that a ValueError gets raised when attempting to write a
        UsernamePasswordCredential struct missing username data to a data
        stream.
        """
        credential = objects.UsernamePasswordCredential(
            password="password1"
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Username/password credential struct missing the username.",
            credential.write,
            *args
        )

    def test_write_missing_password(self):
        """
        Test that a UsernamePasswordCredential struct missing password data
        can be written to a data stream.
        """
        credential = objects.UsernamePasswordCredential(
            username="Fred"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(len(self.encoding_missing_password), len(stream))
        self.assertEqual(str(self.encoding_missing_password), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        UsernamePasswordCredential structs with the same data.
        """
        a = objects.UsernamePasswordCredential()
        b = objects.UsernamePasswordCredential()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        b = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_username(self):
        """
        Test that the equality operator returns False when comparing two
        UsernamePasswordCredential structs with different usernames.
        """
        a = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        b = objects.UsernamePasswordCredential(
            username="Wilma",
            password="password1"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_password(self):
        """
        Test that the equality operator returns False when comparing two
        UsernamePasswordCredential structs with different passwords.
        """
        a = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        b = objects.UsernamePasswordCredential(
            username="Fred",
            password="1password"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        UsernamePasswordCredential structs with different types.
        """
        a = objects.UsernamePasswordCredential()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        UsernamePasswordCredential structs with the same data.
        """
        a = objects.UsernamePasswordCredential()
        b = objects.UsernamePasswordCredential()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        b = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_username(self):
        """
        Test that the inequality operator returns True when comparing two
        UsernamePasswordCredential structs with different usernames.
        """
        a = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        b = objects.UsernamePasswordCredential(
            username="Wilma",
            password="password1"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_password(self):
        """
        Test that the inequality operator returns True when comparing two
        UsernamePasswordCredential structs with different passwords.
        """
        a = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        b = objects.UsernamePasswordCredential(
            username="Fred",
            password="1password"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        UsernamePasswordCredential structs with different types.
        """
        a = objects.UsernamePasswordCredential()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a UsernamePasswordCredential struct.
        """
        credential = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        expected = (
            "UsernamePasswordCredential("
            "username='Fred', "
            "password='password1')"
        )
        observed = repr(credential)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a UsernamePasswordCredential struct.
        """
        credential = objects.UsernamePasswordCredential(
            username="Fred",
            password="password1"
        )
        expected = str({"username": "Fred", "password": "password1"})
        observed = str(credential)

        self.assertEqual(expected, observed)

class TestDeviceCredential(testtools.TestCase):
    """
    Test suite for the DeviceCredential struct.
    """

    def setUp(self):
        super(TestDeviceCredential, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 11.2.
        #
        # This encoding matches the following set of values:
        # DeviceCredential
        #     Device Serial Number - serNum123456
        #     Password - secret
        #     Device Identifier - devID2233
        #     Network Identifier - netID9000
        #     Machine Identifier - machineID1
        #     Media Identifier - mediaID313
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x88'
            b'\x42\x00\xB0\x07\x00\x00\x00\x0C'
            b'\x73\x65\x72\x4E\x75\x6D\x31\x32\x33\x34\x35\x36\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x06'
            b'\x73\x65\x63\x72\x65\x74\x00\x00'
            b'\x42\x00\xA2\x07\x00\x00\x00\x09'
            b'\x64\x65\x76\x49\x44\x32\x32\x33\x33\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAB\x07\x00\x00\x00\x09'
            b'\x6E\x65\x74\x49\x44\x39\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA9\x07\x00\x00\x00\x0A'
            b'\x6D\x61\x63\x68\x69\x6E\x65\x49\x44\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAA\x07\x00\x00\x00\x0A'
            b'\x6D\x65\x64\x69\x61\x49\x44\x33\x31\x33\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_device_serial_number = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x70'
            b'\x42\x00\xA1\x07\x00\x00\x00\x06'
            b'\x73\x65\x63\x72\x65\x74\x00\x00'
            b'\x42\x00\xA2\x07\x00\x00\x00\x09'
            b'\x64\x65\x76\x49\x44\x32\x32\x33\x33\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAB\x07\x00\x00\x00\x09'
            b'\x6E\x65\x74\x49\x44\x39\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA9\x07\x00\x00\x00\x0A'
            b'\x6D\x61\x63\x68\x69\x6E\x65\x49\x44\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAA\x07\x00\x00\x00\x0A'
            b'\x6D\x65\x64\x69\x61\x49\x44\x33\x31\x33\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_password = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x78'
            b'\x42\x00\xB0\x07\x00\x00\x00\x0C'
            b'\x73\x65\x72\x4E\x75\x6D\x31\x32\x33\x34\x35\x36\x00\x00\x00\x00'
            b'\x42\x00\xA2\x07\x00\x00\x00\x09'
            b'\x64\x65\x76\x49\x44\x32\x32\x33\x33\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAB\x07\x00\x00\x00\x09'
            b'\x6E\x65\x74\x49\x44\x39\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA9\x07\x00\x00\x00\x0A'
            b'\x6D\x61\x63\x68\x69\x6E\x65\x49\x44\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAA\x07\x00\x00\x00\x0A'
            b'\x6D\x65\x64\x69\x61\x49\x44\x33\x31\x33\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_device_identifier = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x70'
            b'\x42\x00\xB0\x07\x00\x00\x00\x0C'
            b'\x73\x65\x72\x4E\x75\x6D\x31\x32\x33\x34\x35\x36\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x06'
            b'\x73\x65\x63\x72\x65\x74\x00\x00'
            b'\x42\x00\xAB\x07\x00\x00\x00\x09'
            b'\x6E\x65\x74\x49\x44\x39\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA9\x07\x00\x00\x00\x0A'
            b'\x6D\x61\x63\x68\x69\x6E\x65\x49\x44\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAA\x07\x00\x00\x00\x0A'
            b'\x6D\x65\x64\x69\x61\x49\x44\x33\x31\x33\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_network_identifier = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x70'
            b'\x42\x00\xB0\x07\x00\x00\x00\x0C'
            b'\x73\x65\x72\x4E\x75\x6D\x31\x32\x33\x34\x35\x36\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x06'
            b'\x73\x65\x63\x72\x65\x74\x00\x00'
            b'\x42\x00\xA2\x07\x00\x00\x00\x09'
            b'\x64\x65\x76\x49\x44\x32\x32\x33\x33\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA9\x07\x00\x00\x00\x0A'
            b'\x6D\x61\x63\x68\x69\x6E\x65\x49\x44\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAA\x07\x00\x00\x00\x0A'
            b'\x6D\x65\x64\x69\x61\x49\x44\x33\x31\x33\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_machine_identifier = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x70'
            b'\x42\x00\xB0\x07\x00\x00\x00\x0C'
            b'\x73\x65\x72\x4E\x75\x6D\x31\x32\x33\x34\x35\x36\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x06'
            b'\x73\x65\x63\x72\x65\x74\x00\x00'
            b'\x42\x00\xA2\x07\x00\x00\x00\x09'
            b'\x64\x65\x76\x49\x44\x32\x32\x33\x33\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAB\x07\x00\x00\x00\x09'
            b'\x6E\x65\x74\x49\x44\x39\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAA\x07\x00\x00\x00\x0A'
            b'\x6D\x65\x64\x69\x61\x49\x44\x33\x31\x33\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_media_identifier = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x70'
            b'\x42\x00\xB0\x07\x00\x00\x00\x0C'
            b'\x73\x65\x72\x4E\x75\x6D\x31\x32\x33\x34\x35\x36\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x06'
            b'\x73\x65\x63\x72\x65\x74\x00\x00'
            b'\x42\x00\xA2\x07\x00\x00\x00\x09'
            b'\x64\x65\x76\x49\x44\x32\x32\x33\x33\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAB\x07\x00\x00\x00\x09'
            b'\x6E\x65\x74\x49\x44\x39\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA9\x07\x00\x00\x00\x0A'
            b'\x6D\x61\x63\x68\x69\x6E\x65\x49\x44\x31\x00\x00\x00\x00\x00\x00'
        )
        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestDeviceCredential, self).tearDown()

    def test_init(self):
        """
        Test that a DeviceCredential struct can be constructed without
        arguments.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

    def test_init_with_args(self):
        """
        Test that a DeviceCredential struct can be constructed with arguments.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )

        self.assertEqual("serNum123456", credential.device_serial_number)
        self.assertEqual("secret", credential.password)
        self.assertEqual("devID2233", credential.device_identifier)
        self.assertEqual("netID9000", credential.network_identifier)
        self.assertEqual("machineID1", credential.machine_identifier)
        self.assertEqual("mediaID313", credential.media_identifier)

    def test_invalid_device_serial_number(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the device serial number of a DeviceCredential struct.
        """
        kwargs = {'device_serial_number': 0}
        self.assertRaisesRegex(
            TypeError,
            "Device serial number must be a string.",
            objects.DeviceCredential,
            **kwargs
        )

        credential = objects.DeviceCredential()
        args = (credential, "device_serial_number", 0)
        self.assertRaisesRegex(
            TypeError,
            "Device serial number must be a string.",
            setattr,
            *args
        )

    def test_invalid_password(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the password of a DeviceCredential struct.
        """
        kwargs = {'password': 0}
        self.assertRaisesRegex(
            TypeError,
            "Password must be a string.",
            objects.DeviceCredential,
            **kwargs
        )

        credential = objects.DeviceCredential()
        args = (credential, "password", 0)
        self.assertRaisesRegex(
            TypeError,
            "Password must be a string.",
            setattr,
            *args
        )

    def test_invalid_device_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the device identifier of a DeviceCredential struct.
        """
        kwargs = {'device_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Device identifier must be a string.",
            objects.DeviceCredential,
            **kwargs
        )

        credential = objects.DeviceCredential()
        args = (credential, "device_identifier", 0)
        self.assertRaisesRegex(
            TypeError,
            "Device identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_network_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the network identifier of a DeviceCredential struct.
        """
        kwargs = {'network_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Network identifier must be a string.",
            objects.DeviceCredential,
            **kwargs
        )

        credential = objects.DeviceCredential()
        args = (credential, "network_identifier", 0)
        self.assertRaisesRegex(
            TypeError,
            "Network identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_machine_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the machine identifier of a DeviceCredential struct.
        """
        kwargs = {'machine_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Machine identifier must be a string.",
            objects.DeviceCredential,
            **kwargs
        )

        credential = objects.DeviceCredential()
        args = (credential, "machine_identifier", 0)
        self.assertRaisesRegex(
            TypeError,
            "Machine identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_media_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the media identifier of a DeviceCredential struct.
        """
        kwargs = {'media_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Media identifier must be a string.",
            objects.DeviceCredential,
            **kwargs
        )

        credential = objects.DeviceCredential()
        args = (credential, "media_identifier", 0)
        self.assertRaisesRegex(
            TypeError,
            "Media identifier must be a string.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a DeviceCredential struct can be read from a data stream.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.full_encoding)

        self.assertEqual("serNum123456", credential.device_serial_number)
        self.assertEqual("secret", credential.password)
        self.assertEqual("devID2233", credential.device_identifier)
        self.assertEqual("netID9000", credential.network_identifier)
        self.assertEqual("machineID1", credential.machine_identifier)
        self.assertEqual("mediaID313", credential.media_identifier)

    def test_read_missing_device_serial_number(self):
        """
        Test that a DeviceCredential struct can be read from a data stream
        missing the device serial number data.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.encoding_missing_device_serial_number)

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual("secret", credential.password)
        self.assertEqual("devID2233", credential.device_identifier)
        self.assertEqual("netID9000", credential.network_identifier)
        self.assertEqual("machineID1", credential.machine_identifier)
        self.assertEqual("mediaID313", credential.media_identifier)

    def test_read_missing_password(self):
        """
        Test that a DeviceCredential struct can be read from a data stream
        missing the password data.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.encoding_missing_password)

        self.assertEqual("serNum123456", credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual("devID2233", credential.device_identifier)
        self.assertEqual("netID9000", credential.network_identifier)
        self.assertEqual("machineID1", credential.machine_identifier)
        self.assertEqual("mediaID313", credential.media_identifier)

    def test_read_missing_device_identifier(self):
        """
        Test that a DeviceCredential struct can be read from a data stream
        missing the device identifier data.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.encoding_missing_device_identifier)

        self.assertEqual("serNum123456", credential.device_serial_number)
        self.assertEqual("secret", credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual("netID9000", credential.network_identifier)
        self.assertEqual("machineID1", credential.machine_identifier)
        self.assertEqual("mediaID313", credential.media_identifier)

    def test_read_missing_network_identifier(self):
        """
        Test that a DeviceCredential struct can be read from a data stream
        missing the network identifier data.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.encoding_missing_network_identifier)

        self.assertEqual("serNum123456", credential.device_serial_number)
        self.assertEqual("secret", credential.password)
        self.assertEqual("devID2233", credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual("machineID1", credential.machine_identifier)
        self.assertEqual("mediaID313", credential.media_identifier)

    def test_read_missing_machine_identifier(self):
        """
        Test that a DeviceCredential struct can be read from a data stream
        missing the machine identifier data.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.encoding_missing_machine_identifier)

        self.assertEqual("serNum123456", credential.device_serial_number)
        self.assertEqual("secret", credential.password)
        self.assertEqual("devID2233", credential.device_identifier)
        self.assertEqual("netID9000", credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual("mediaID313", credential.media_identifier)

    def test_read_missing_media_identifier(self):
        """
        Test that a DeviceCredential struct can be read from a data stream
        missing the media identifier data.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.encoding_missing_media_identifier)

        self.assertEqual("serNum123456", credential.device_serial_number)
        self.assertEqual("secret", credential.password)
        self.assertEqual("devID2233", credential.device_identifier)
        self.assertEqual("netID9000", credential.network_identifier)
        self.assertEqual("machineID1", credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

    def test_read_missing_everything(self):
        """
        Test that a DeviceCredential struct can be read from a data stream
        missing all data.
        """
        credential = objects.DeviceCredential()

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

        credential.read(self.empty_encoding)

        self.assertEqual(None, credential.device_serial_number)
        self.assertEqual(None, credential.password)
        self.assertEqual(None, credential.device_identifier)
        self.assertEqual(None, credential.network_identifier)
        self.assertEqual(None, credential.machine_identifier)
        self.assertEqual(None, credential.media_identifier)

    def test_write(self):
        """
        Test that a DeviceCredential struct can be written to a data stream.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_device_serial_number(self):
        """
        Test that a DeviceCredential struct missing device serial number data
        can be written to a data stream.
        """
        credential = objects.DeviceCredential(
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(
            len(self.encoding_missing_device_serial_number),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_missing_device_serial_number),
            str(stream)
        )

    def test_write_missing_password(self):
        """
        Test that a DeviceCredential struct missing password data can be
        written to a data stream.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(len(self.encoding_missing_password), len(stream))
        self.assertEqual(str(self.encoding_missing_password), str(stream))

    def test_write_missing_device_identifier(self):
        """
        Test that a DeviceCredential struct missing device identifier data can
        be written to a data stream.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(
            len(self.encoding_missing_device_identifier),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_missing_device_identifier),
            str(stream)
        )

    def test_write_missing_network_identifier(self):
        """
        Test that a DeviceCredential struct missing network identifier data
        can be written to a data stream.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(
            len(self.encoding_missing_network_identifier),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_missing_network_identifier),
            str(stream)
        )

    def test_write_missing_machine_identifier(self):
        """
        Test that a DeviceCredential struct missing machine identifier data
        can be written to a data stream.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            media_identifier="mediaID313"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(
            len(self.encoding_missing_machine_identifier),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_missing_machine_identifier),
            str(stream)
        )

    def test_write_missing_media_identifier(self):
        """
        Test that a DeviceCredential struct missing media identifier data can
        be written to a data stream.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1"
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(
            len(self.encoding_missing_media_identifier),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_missing_media_identifier),
            str(stream)
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        DeviceCredential structs with the same data.
        """
        a = objects.DeviceCredential()
        b = objects.DeviceCredential()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        b = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_device_serial_number(self):
        """
        Test that the equality operator returns False when comparing two
        DeviceCredential structs with different device serial numbers.
        """
        a = objects.DeviceCredential(
            device_serial_number="serNum123456"
        )
        b = objects.DeviceCredential(
            device_serial_number="serNum654321"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_password(self):
        """
        Test that the equality operator returns False when comparing two
        DeviceCredential structs with different passwords.
        """
        a = objects.DeviceCredential(
            password="secret"
        )
        b = objects.DeviceCredential(
            password="public"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_device_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        DeviceCredential structs with different device identifiers.
        """
        a = objects.DeviceCredential(
            device_identifier="devID2233"
        )
        b = objects.DeviceCredential(
            device_identifier="devID0011"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_network_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        DeviceCredential structs with different network identifiers.
        """
        a = objects.DeviceCredential(
            network_identifier="netID9000"
        )
        b = objects.DeviceCredential(
            network_identifier="netID0999"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_machine_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different machine identifiers.
        """
        a = objects.DeviceCredential(
            machine_identifier="machineID1"
        )
        b = objects.DeviceCredential(
            machine_identifier="machineID2"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_media_identifier(self):
        """
        Test that the equality operator returns False when comparing two
        DeviceCredential structs with different media identifiers.
        """
        a = objects.DeviceCredential(
            media_identifier="mediaID313"
        )
        b = objects.DeviceCredential(
            media_identifier="mediaID828"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        DeviceCredential structs with different types.
        """
        a = objects.DeviceCredential()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        DeviceCredential structs with the same data.
        """
        a = objects.DeviceCredential()
        b = objects.DeviceCredential()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        b = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_device_serial_number(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different device serial numbers.
        """
        a = objects.DeviceCredential(
            device_serial_number="serNum123456"
        )
        b = objects.DeviceCredential(
            device_serial_number="serNum654321"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_password(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different passwords.
        """
        a = objects.DeviceCredential(
            password="secret"
        )
        b = objects.DeviceCredential(
            password="public"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_device_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different device identifiers.
        """
        a = objects.DeviceCredential(
            device_identifier="devID2233"
        )
        b = objects.DeviceCredential(
            device_identifier="devID0011"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_network_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different network identifiers.
        """
        a = objects.DeviceCredential(
            network_identifier="netID9000"
        )
        b = objects.DeviceCredential(
            network_identifier="netID0999"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_machine_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different machine identifiers.
        """
        a = objects.DeviceCredential(
            machine_identifier="machineID1"
        )
        b = objects.DeviceCredential(
            machine_identifier="machineID2"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_media_identifier(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different media identifiers.
        """
        a = objects.DeviceCredential(
            media_identifier="mediaID313"
        )
        b = objects.DeviceCredential(
            media_identifier="mediaID828"
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        DeviceCredential structs with different types.
        """
        a = objects.DeviceCredential()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a DeviceCredential struct.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        expected = (
            "DeviceCredential("
            "device_serial_number='serNum123456', "
            "password='secret', "
            "device_identifier='devID2233', "
            "network_identifier='netID9000', "
            "machine_identifier='machineID1', "
            "media_identifier='mediaID313')"
        )
        observed = repr(credential)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a DeviceCredential struct.
        """
        credential = objects.DeviceCredential(
            device_serial_number="serNum123456",
            password="secret",
            device_identifier="devID2233",
            network_identifier="netID9000",
            machine_identifier="machineID1",
            media_identifier="mediaID313"
        )
        expected = str(
            {
                "device_serial_number": "serNum123456",
                "password": "secret",
                "device_identifier": "devID2233",
                "network_identifier": "netID9000",
                "machine_identifier": "machineID1",
                "media_identifier": "mediaID313"
            }
        )
        observed = str(credential)

        self.assertEqual(expected, observed)

class TestAttestationCredential(testtools.TestCase):
    """
    Test suite for the AttestationCredential struct.
    """

    def setUp(self):
        super(TestAttestationCredential, self).setUp()

        # There are no AttestationCredential encodings available in any of the
        # KMIP testing documents. The following encodings were adapted from
        # other structure encodings present in the KMIP testing suite.
        #
        # This encoding matches the following set of values:
        # AttestationCredential
        #     Nonce
        #         Nonce ID - 1
        #         Nonce Value - 0x0001020304050607
        #     AttestationType - TPM Quote
        #     AttestationMeasurement - 0xFFFFFFFFFFFFFFFF
        #     AttestationAssertion - 0x1111111111111111
        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x58'
            b'\x42\x00\xC8\x01\x00\x00\x00\x20'
            b'\x42\x00\xC9\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xCA\x08\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xCB\x08\x00\x00\x00\x08\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            b'\x42\x00\xCC\x08\x00\x00\x00\x08\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        self.encoding_missing_nonce = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x30'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xCB\x08\x00\x00\x00\x08\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            b'\x42\x00\xCC\x08\x00\x00\x00\x08\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        self.encoding_missing_attestation_type = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x48'
            b'\x42\x00\xC8\x01\x00\x00\x00\x20'
            b'\x42\x00\xC9\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xCA\x08\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x42\x00\xCB\x08\x00\x00\x00\x08\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
            b'\x42\x00\xCC\x08\x00\x00\x00\x08\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        self.encoding_missing_attestation_measurement = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x48'
            b'\x42\x00\xC8\x01\x00\x00\x00\x20'
            b'\x42\x00\xC9\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xCA\x08\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xCC\x08\x00\x00\x00\x08\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        self.encoding_missing_attestation_assertion = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x48'
            b'\x42\x00\xC8\x01\x00\x00\x00\x20'
            b'\x42\x00\xC9\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xCA\x08\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\xCB\x08\x00\x00\x00\x08\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        )
        self.encoding_missing_attestation = utils.BytearrayStream(
            b'\x42\x00\x25\x01\x00\x00\x00\x38'
            b'\x42\x00\xC8\x01\x00\x00\x00\x20'
            b'\x42\x00\xC9\x08\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xCA\x08\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07'
            b'\x42\x00\xC7\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestAttestationCredential, self).tearDown()

    def test_init(self):
        """
        Test that an AttestationCredential struct can be constructed without
        arguments.
        """
        credential = objects.AttestationCredential()

        self.assertEqual(None, credential.nonce)
        self.assertEqual(None, credential.attestation_type)
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(None, credential.attestation_assertion)

    def test_init_with_args(self):
        """
        Test that an AttestationCredential struct can be constructed with
        arguments.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )

        self.assertEqual(
            objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            credential.nonce
        )
        self.assertEqual(
            enums.AttestationType.TPM_QUOTE,
            credential.attestation_type
        )
        self.assertEqual(
            b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            credential.attestation_measurement
        )
        self.assertEqual(
            b'\x11\x11\x11\x11\x11\x11\x11\x11',
            credential.attestation_assertion
        )

    def test_invalid_nonce(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the nonce of an AttestationCredential struct.
        """
        kwargs = {"nonce": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Nonce must be a Nonce struct.",
            objects.AttestationCredential,
            **kwargs
        )

        credential = objects.AttestationCredential()
        args = (credential, "nonce", 0)
        self.assertRaisesRegex(
            TypeError,
            "Nonce must be a Nonce struct.",
            setattr,
            *args
        )

    def test_invalid_attestation_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attestation type of an AttestationCredential struct.
        """
        kwargs = {"attestation_type": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Attestation type must be an AttestationType enumeration.",
            objects.AttestationCredential,
            **kwargs
        )

        credential = objects.AttestationCredential()
        args = (credential, "attestation_type", 0)
        self.assertRaisesRegex(
            TypeError,
            "Attestation type must be an AttestationType enumeration.",
            setattr,
            *args
        )

    def test_invalid_attestation_measurement(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attestation measurement of an AttestationCredential struct.
        """
        kwargs = {"attestation_measurement": 0}
        self.assertRaisesRegex(
            TypeError,
            "Attestation measurement must be bytes.",
            objects.AttestationCredential,
            **kwargs
        )

        credential = objects.AttestationCredential()
        args = (credential, "attestation_measurement", 0)
        self.assertRaisesRegex(
            TypeError,
            "Attestation measurement must be bytes.",
            setattr,
            *args
        )

    def test_invalid_attestation_assertion(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the attestation assertion of an AttestationCredential struct.
        """
        kwargs = {"attestation_assertion": 0}
        self.assertRaisesRegex(
            TypeError,
            "Attestation assertion must be bytes.",
            objects.AttestationCredential,
            **kwargs
        )

        credential = objects.AttestationCredential()
        args = (credential, "attestation_assertion", 0)
        self.assertRaisesRegex(
            TypeError,
            "Attestation assertion must be bytes.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an AttestationCredential struct can be read from a data
        stream.
        """
        credential = objects.AttestationCredential()

        self.assertEqual(None, credential.nonce)
        self.assertEqual(None, credential.attestation_type)
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(None, credential.attestation_assertion)

        credential.read(self.full_encoding)

        self.assertEqual(
            objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            credential.nonce
        )
        self.assertEqual(
            enums.AttestationType.TPM_QUOTE,
            credential.attestation_type
        )
        self.assertEqual(
            b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            credential.attestation_measurement
        )
        self.assertEqual(
            b'\x11\x11\x11\x11\x11\x11\x11\x11',
            credential.attestation_assertion
        )

    def test_read_missing_nonce(self):
        """
        Test that a ValueError gets raised when attempting to read an
        AttestationCredential struct from a data stream missing the nonce data.
        """
        credential = objects.AttestationCredential()

        self.assertEqual(None, credential.nonce)
        self.assertEqual(None, credential.attestation_type)
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(None, credential.attestation_assertion)

        args = (self.encoding_missing_nonce, )
        self.assertRaisesRegex(
            ValueError,
            "Attestation credential encoding is missing the nonce.",
            credential.read,
            *args
        )

    def test_read_missing_attestation_type(self):
        """
        Test that a ValueError gets raised when attempting to read an
        AttestationCredential struct from a data stream missing the
        attestation type data.
        """
        credential = objects.AttestationCredential()

        self.assertEqual(None, credential.nonce)
        self.assertEqual(None, credential.attestation_type)
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(None, credential.attestation_assertion)

        args = (self.encoding_missing_attestation_type, )
        self.assertRaisesRegex(
            ValueError,
            "Attestation credential encoding is missing the attestation type.",
            credential.read,
            *args
        )

    def test_read_missing_attestation_measurement(self):
        """
        Test that an AttestationCredential struct can be read from a data
        stream missing the attestation measurement data.
        """
        credential = objects.AttestationCredential()

        self.assertEqual(None, credential.nonce)
        self.assertEqual(None, credential.attestation_type)
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(None, credential.attestation_assertion)

        credential.read(self.encoding_missing_attestation_measurement)

        self.assertEqual(
            objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            credential.nonce
        )
        self.assertEqual(
            enums.AttestationType.TPM_QUOTE,
            credential.attestation_type
        )
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(
            b'\x11\x11\x11\x11\x11\x11\x11\x11',
            credential.attestation_assertion
        )

    def test_read_missing_attestation_assertion(self):
        """
        Test that an AttestationCredential struct can be read from a data
        stream missing the attestation assertion data.
        """

        credential = objects.AttestationCredential()

        self.assertEqual(None, credential.nonce)
        self.assertEqual(None, credential.attestation_type)
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(None, credential.attestation_assertion)

        credential.read(self.encoding_missing_attestation_assertion)

        self.assertEqual(
            objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            credential.nonce
        )
        self.assertEqual(
            enums.AttestationType.TPM_QUOTE,
            credential.attestation_type
        )
        self.assertEqual(
            b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            credential.attestation_measurement
        )
        self.assertEqual(None, credential.attestation_assertion)

    def test_read_missing_attestation_measurement_and_assertion(self):
        """
        Test that a ValueError gets raised when attempting to read an
        AttestationCredential struct from a data stream missing both the
        attestation measurement and attestation assertion data.
        """
        credential = objects.AttestationCredential()

        self.assertEqual(None, credential.nonce)
        self.assertEqual(None, credential.attestation_type)
        self.assertEqual(None, credential.attestation_measurement)
        self.assertEqual(None, credential.attestation_assertion)

        args = (self.encoding_missing_attestation, )
        self.assertRaisesRegex(
            ValueError,
            "Attestation credential encoding is missing either the "
            "attestation measurement or the attestation assertion.",
            credential.read,
            *args
        )

    def test_write(self):
        """
        Test that an AttestationCredential struct can be written to a data
        stream.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_missing_nonce(self):
        """
        Test that a ValueError gets raised when attempting to write an
        AttestationCredential struct missing nonce data to a data stream.
        """
        credential = objects.AttestationCredential(
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Attestation credential struct is missing the nonce.",
            credential.write,
            *args
        )

    def test_write_missing_attestation_type(self):
        """
        Test that a ValueError gets raised when attempting to write an
        AttestationCredential struct missing nonce data to a data stream.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Attestation credential struct is missing the attestation type.",
            credential.write,
            *args
        )

    def test_write_missing_attestation_measurement(self):
        """
        Test that an AttestationCredential struct can be written to a data
        stream missing attestation measurement data.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(
            len(self.encoding_missing_attestation_measurement),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_missing_attestation_measurement),
            str(stream)
        )

    def test_write_missing_attestation_assertion(self):
        """
        Test that an AttestationCredential struct can be written to a data
        stream missing attestation assertion data.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(
            len(self.encoding_missing_attestation_assertion),
            len(stream)
        )
        self.assertEqual(
            str(self.encoding_missing_attestation_assertion),
            str(stream)
        )

    def test_write_missing_attestation_measurement_and_assertion(self):
        """
        Test that a ValueError gets raised when attempting to write an
        AttestationCredential struct missing both attestation measurement and
        attestation assertion data to a data stream.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Attestation credential struct is missing either the attestation "
            "measurement or the attestation assertion.",
            credential.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        AttestationCredential structs with the same data.
        """
        a = objects.AttestationCredential()
        b = objects.AttestationCredential()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        b = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_nonce(self):
        """
        Test that the equality operator returns False when comparing two
        AttestationCredential structs with different nonce values.
        """
        a = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            )
        )
        b = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x02',
                nonce_value=b'\x07\x06\x05\x04\x03\x02\x01\x00'
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attestation_type(self):
        """
        Test that the equality operator returns False when comparing two
        AttestationCredential structs with different attestation types.
        """
        a = objects.AttestationCredential(
            attestation_type=enums.AttestationType.TPM_QUOTE
        )
        b = objects.AttestationCredential(
            attestation_type=enums.AttestationType.SAML_ASSERTION
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attestation_measurement(self):
        """
        Test that the equality operator returns False when comparing two
        AttestationCredential structs with different attestation measurements.
        """
        a = objects.AttestationCredential(
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        )
        b = objects.AttestationCredential(
            attestation_measurement=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_attestation_assertion(self):
        """
        Test that the equality operator returns False when comparing two
        AttestationCredential structs with different attestation assertions.
        """
        a = objects.AttestationCredential(
            attestation_assertion=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        )
        b = objects.AttestationCredential(
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        AttestationCredential structs with different types.
        """
        a = objects.AttestationCredential()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        AttestationCredential structs with the same data.
        """
        a = objects.AttestationCredential()
        b = objects.AttestationCredential()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        b = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_nonce(self):
        """
        Test that the inequality operator returns True when comparing two
        AttestationCredential structs with different nonce values.
        """
        a = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            )
        )
        b = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x02',
                nonce_value=b'\x07\x06\x05\x04\x03\x02\x01\x00'
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attestation_type(self):
        """
        Test that the inequality operator returns True when comparing two
        AttestationCredential structs with different attestation types.
        """
        a = objects.AttestationCredential(
            attestation_type=enums.AttestationType.TPM_QUOTE
        )
        b = objects.AttestationCredential(
            attestation_type=enums.AttestationType.SAML_ASSERTION
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attestation_measurement(self):
        """
        Test that the inequality operator returns True when comparing two
        AttestationCredential structs with different attestation measurements.
        """
        a = objects.AttestationCredential(
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        )
        b = objects.AttestationCredential(
            attestation_measurement=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_attestation_assertion(self):
        """
        Test that the inequality operator returns True when comparing two
        AttestationCredential structs with different attestation assertions.
        """
        a = objects.AttestationCredential(
            attestation_assertion=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
        )
        b = objects.AttestationCredential(
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        AttestationCredential structs with different types.
        """
        a = objects.AttestationCredential()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an AttestationCredential struct.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        expected = (
            "AttestationCredential("
            "nonce=Nonce("
            "nonce_id=" + str(b'\x01') + ", "
            "nonce_value=" + str(b'\x00\x01\x02\x03\x04\x05\x06\x07') + "), "
            "attestation_type=AttestationType.TPM_QUOTE, "
            "attestation_measurement=" +
            str(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF') + ", "
            "attestation_assertion=" +
            str(b'\x11\x11\x11\x11\x11\x11\x11\x11') + ")"
        )
        observed = repr(credential)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an AttestationCredential struct.
        """
        credential = objects.AttestationCredential(
            nonce=objects.Nonce(
                nonce_id=b'\x01',
                nonce_value=b'\x00\x01\x02\x03\x04\x05\x06\x07'
            ),
            attestation_type=enums.AttestationType.TPM_QUOTE,
            attestation_measurement=b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF',
            attestation_assertion=b'\x11\x11\x11\x11\x11\x11\x11\x11'
        )
        expected = "{" \
                   "'nonce': {" \
                   "'nonce_id': " + str(b'\x01') + ", " \
                   "'nonce_value': " + \
                   str(b'\x00\x01\x02\x03\x04\x05\x06\x07') + "}, " \
                   "'attestation_type': " + \
                   str(enums.AttestationType.TPM_QUOTE) + ", " \
                   "'attestation_measurement': " + \
                   str(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF') + ", " \
                   "'attestation_assertion': " + \
                   str(b'\x11\x11\x11\x11\x11\x11\x11\x11') + "}"
        observed = str(credential)

        self.assertEqual(expected, observed)

class TestCredential(testtools.TestCase):
    """
    Test suite for the Credential struct.
    """

    def setUp(self):
        super(TestCredential, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 11.1.
        #
        # This encoding matches the following set of values:
        # Credential
        #     CredentialType - Username and Password
        #     CredentialValue
        #         Username - Fred
        #         Password - password1
        self.username_password_encoding = utils.BytearrayStream(
            b'\x42\x00\x23\x01\x00\x00\x00\x40'
            b'\x42\x00\x24\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x25\x01\x00\x00\x00\x28'
            b'\x42\x00\x99\x07\x00\x00\x00\x04'
            b'\x46\x72\x65\x64\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x09'
            b'\x70\x61\x73\x73\x77\x6F\x72\x64\x31\x00\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_credential_type = utils.BytearrayStream(
            b'\x42\x00\x23\x01\x00\x00\x00\x30'
            b'\x42\x00\x25\x01\x00\x00\x00\x28'
            b'\x42\x00\x99\x07\x00\x00\x00\x04'
            b'\x46\x72\x65\x64\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x09'
            b'\x70\x61\x73\x73\x77\x6F\x72\x64\x31\x00\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_credential_value = utils.BytearrayStream(
            b'\x42\x00\x23\x01\x00\x00\x00\x10'
            b'\x42\x00\x24\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
        )
        self.encoding_unknown_credential_type = utils.BytearrayStream(
            b'\x42\x00\x23\x01\x00\x00\x00\x40'
            b'\x42\x00\x24\x05\x00\x00\x00\x04\x00\x00\x00\xFF\x00\x00\x00\x00'
            b'\x42\x00\x25\x01\x00\x00\x00\x28'
            b'\x42\x00\x99\x07\x00\x00\x00\x04'
            b'\x46\x72\x65\x64\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x09'
            b'\x70\x61\x73\x73\x77\x6F\x72\x64\x31\x00\x00\x00\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 11.2.
        #
        # This encoding matches the following set of values:
        # Credential
        #     CredentialType - Device
        #     CredentialValue
        #         Device Serial Number - serNum123456
        #         Password - secret
        #         Device Identifier - devID2233
        #         Network Identifier - netID9000
        #         Machine Identifier - machineID1
        #         Media Identifier - mediaID313
        self.device_encoding = utils.BytearrayStream(
            b'\x42\x00\x23\x01\x00\x00\x00\xA0'
            b'\x42\x00\x24\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00'
            b'\x42\x00\x25\x01\x00\x00\x00\x88'
            b'\x42\x00\xB0\x07\x00\x00\x00\x0C'
            b'\x73\x65\x72\x4E\x75\x6D\x31\x32\x33\x34\x35\x36\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x06'
            b'\x73\x65\x63\x72\x65\x74\x00\x00'
            b'\x42\x00\xA2\x07\x00\x00\x00\x09'
            b'\x64\x65\x76\x49\x44\x32\x32\x33\x33\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAB\x07\x00\x00\x00\x09'
            b'\x6E\x65\x74\x49\x44\x39\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xA9\x07\x00\x00\x00\x0A'
            b'\x6D\x61\x63\x68\x69\x6E\x65\x49\x44\x31\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\xAA\x07\x00\x00\x00\x0A'
            b'\x6D\x65\x64\x69\x61\x49\x44\x33\x31\x33\x00\x00\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestCredential, self).tearDown()

    def test_init(self):
        """
        Test that a Credential struct can be constructed without arguments.
        """
        credential = objects.Credential()

        self.assertEqual(None, credential.credential_type)
        self.assertEqual(None, credential.credential_value)

    def test_init_with_args(self):
        """
        Test that a Credential struct can be constructed with arguments.
        """
        credential = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="John",
                password="abc123"
            )
        )

        self.assertEqual(
            enums.CredentialType.USERNAME_AND_PASSWORD,
            credential.credential_type
        )
        self.assertEqual(
            objects.UsernamePasswordCredential(
                username="John",
                password="abc123"
            ),
            credential.credential_value
        )

    def test_invalid_credential_type(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the credential type of a Credential struct.
        """
        kwargs = {"credential_type": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Credential type must be a CredentialType enumeration.",
            objects.Credential,
            **kwargs
        )

        credential = objects.Credential()
        args = (credential, "credential_type", 0)
        self.assertRaisesRegex(
            TypeError,
            "Credential type must be a CredentialType enumeration.",
            setattr,
            *args
        )

    def test_invalid_credential_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the credential value of a Credential struct.
        """
        kwargs = {"credential_value": "invalid"}
        self.assertRaisesRegex(
            TypeError,
            "Credential value must be a CredentialValue struct.",
            objects.Credential,
            **kwargs
        )

        credential = objects.Credential()
        args = (credential, "credential_value", 0)
        self.assertRaisesRegex(
            TypeError,
            "Credential value must be a CredentialValue struct.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Credential struct can be read from a data stream.
        """
        # Test with a UsernamePasswordCredential.
        credential = objects.Credential()

        self.assertEqual(None, credential.credential_type)
        self.assertEqual(None, credential.credential_value)

        credential.read(self.username_password_encoding)

        self.assertEqual(
            enums.CredentialType.USERNAME_AND_PASSWORD,
            credential.credential_type
        )
        self.assertEqual(
            objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            ),
            credential.credential_value
        )

        # Test with a DeviceCredential
        credential = objects.Credential()

        self.assertEqual(None, credential.credential_type)
        self.assertEqual(None, credential.credential_value)

        credential.read(self.device_encoding)

        self.assertEqual(
            enums.CredentialType.DEVICE,
            credential.credential_type
        )
        self.assertEqual(
            objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            ),
            credential.credential_value
        )

    def test_read_missing_credential_type(self):
        """
        Test that a ValueError gets raised when attempting to read a
        Credential struct from a data stream missing the credential type data.
        """
        credential = objects.Credential()

        self.assertEqual(None, credential.credential_type)
        self.assertEqual(None, credential.credential_value)

        args = (self.encoding_missing_credential_type, )
        self.assertRaisesRegex(
            ValueError,
            "Credential encoding missing the credential type.",
            credential.read,
            *args
        )

    @mock.patch(
        'kmip.core.enums.CredentialType',
        enum.Enum(
            'FakeCredentialType',
            [(i.name, i.value) for i in enums.CredentialType] +
            [('UNKNOWN', 0x000000FF)]
        )
    )
    def test_read_unknown_credential_type(self):
        """
        Test that a ValueError gets raised when attempting to read a
        Credential struct from a data stream with an unknown credential
        type.
        """
        credential = objects.Credential()

        self.assertEqual(None, credential.credential_type)
        self.assertEqual(None, credential.credential_value)

        args = (self.encoding_unknown_credential_type, )
        self.assertRaisesRegex(
            ValueError,
            "Credential encoding includes unrecognized credential type.",
            credential.read,
            *args
        )

    def test_read_missing_credential_value(self):
        """
        Test that a ValueError gets raised when attempting to read a
        Credential struct from a data stream missing the credential value
        data.
        """
        credential = objects.Credential()

        self.assertEqual(None, credential.credential_type)
        self.assertEqual(None, credential.credential_value)

        args = (self.encoding_missing_credential_value, )
        self.assertRaisesRegex(
            ValueError,
            "Credential encoding missing the credential value.",
            credential.read,
            *args
        )

    def test_write(self):
        """
        Test that a Credential struct can be written to a data stream.
        """
        # Test with a UsernamePasswordCredential.
        credential = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(len(self.username_password_encoding), len(stream))
        self.assertEqual(str(self.username_password_encoding), str(stream))

        # Test with a DeviceCredential.
        credential = objects.Credential(
            credential_type=enums.CredentialType.DEVICE,
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )
        stream = utils.BytearrayStream()

        credential.write(stream)

        self.assertEqual(len(self.device_encoding), len(stream))
        self.assertEqual(str(self.device_encoding), str(stream))

    def test_write_missing_credential_type(self):
        """
        Test that a ValueError gets raised when attempting to write a
        Credential struct missing credential type data to a data stream.
        """
        credential = objects.Credential(
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Credential struct missing the credential type.",
            credential.write,
            *args
        )

    def test_write_missing_credential_value(self):
        """
        Test that a ValueError gets raised when attempting to write a
        Credential struct missing credential value data to a data stream.
        """
        credential = objects.Credential(
            credential_type=enums.CredentialType.DEVICE
        )
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Credential struct missing the credential value.",
            credential.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Credential structs with the same data.
        """
        a = objects.Credential()
        b = objects.Credential()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        # Test with a UsernamePasswordCredential.
        a = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        b = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        # Test with a DeviceCredential.
        a = objects.Credential(
            credential_type=enums.CredentialType.DEVICE,
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )
        b = objects.Credential(
            credential_type=enums.CredentialType.DEVICE,
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_credential_type(self):
        """
        Test that the equality operator returns False when comparing two
        Credential structs with different credential types.
        """
        a = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD
        )
        b = objects.Credential(
            credential_type=enums.CredentialType.DEVICE
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_credential_value(self):
        """
        Test that the equality operator returns False when comparing two
        Credential structs with different credential values.
        """
        a = objects.Credential(
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        b = objects.Credential(
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Credential structs with different types.
        """
        a = objects.Credential()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Credential structs with the same data.
        """
        a = objects.Credential()
        b = objects.Credential()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        # Test with a UsernamePasswordCredential.
        a = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        b = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        # Test with a DeviceCredential.
        a = objects.Credential(
            credential_type=enums.CredentialType.DEVICE,
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )
        b = objects.Credential(
            credential_type=enums.CredentialType.DEVICE,
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_credential_type(self):
        """
        Test that the inequality operator returns True when comparing two
        Credential structs with different credential types.
        """
        a = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD
        )
        b = objects.Credential(
            credential_type=enums.CredentialType.DEVICE
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_credential_value(self):
        """
        Test that the inequality operator returns True when comparing two
        Credential structs with different credential values.
        """
        a = objects.Credential(
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        b = objects.Credential(
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Credential structs with different types.
        """
        a = objects.Credential()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Credential struct.
        """
        # Test with a UsernamePasswordCredential.
        credential = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        expected = (
            "Credential("
            "credential_type=CredentialType.USERNAME_AND_PASSWORD, "
            "credential_value=UsernamePasswordCredential("
            "username='Fred', "
            "password='password1'))"
        )
        observed = repr(credential)

        self.assertEqual(expected, observed)

        # Test with a DeviceCredential.
        credential = objects.Credential(
            credential_type=enums.CredentialType.DEVICE,
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )
        expected = (
            "Credential("
            "credential_type=CredentialType.DEVICE, "
            "credential_value=DeviceCredential("
            "device_serial_number='serNum123456', "
            "password='secret', "
            "device_identifier='devID2233', "
            "network_identifier='netID9000', "
            "machine_identifier='machineID1', "
            "media_identifier='mediaID313'))"
        )
        observed = repr(credential)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Credential struct.
        """
        # Test with a UsernamePasswordCredential.
        credential = objects.Credential(
            credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
            credential_value=objects.UsernamePasswordCredential(
                username="Fred",
                password="password1"
            )
        )
        expected = str({
            "credential_type": enums.CredentialType.USERNAME_AND_PASSWORD,
            "credential_value": str({
                "username": "Fred",
                "password": "password1"
            })
        })
        observed = str(credential)

        self.assertEqual(expected, observed)

        # Test with a DeviceCredential.
        credential = objects.Credential(
            credential_type=enums.CredentialType.DEVICE,
            credential_value=objects.DeviceCredential(
                device_serial_number="serNum123456",
                password="secret",
                device_identifier="devID2233",
                network_identifier="netID9000",
                machine_identifier="machineID1",
                media_identifier="mediaID313"
            )
        )
        expected = str({
            "credential_type": enums.CredentialType.DEVICE,
            "credential_value": str({
                "device_serial_number": "serNum123456",
                "password": "secret",
                "device_identifier": "devID2233",
                "network_identifier": "netID9000",
                "machine_identifier": "machineID1",
                "media_identifier": "mediaID313"
            })
        })
        observed = str(credential)

        self.assertEqual(expected, observed)
