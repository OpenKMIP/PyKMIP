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

import testtools

from kmip.core import enums
from kmip.core import objects
from kmip.core import utils
from kmip.core.messages import contents

class TestAuthentication(testtools.TestCase):
    """
    Test suite for the Authentication struct.
    """

    def setUp(self):
        super(TestAuthentication, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document, Section 11.1.
        #
        # This encoding matches the following set of values:
        # Authentication
        #     Credential
        #         CredentialType - Username and Password
        #         CredentialValue
        #             Username - Fred
        #             Password - password1
        self.username_password_encoding = utils.BytearrayStream(
            b'\x42\x00\x0C\x01\x00\x00\x00\x48'
            b'\x42\x00\x23\x01\x00\x00\x00\x40'
            b'\x42\x00\x24\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x25\x01\x00\x00\x00\x28'
            b'\x42\x00\x99\x07\x00\x00\x00\x04'
            b'\x46\x72\x65\x64\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x09'
            b'\x70\x61\x73\x73\x77\x6F\x72\x64\x31\x00\x00\x00\x00\x00\x00\x00'
        )
        self.encoding_missing_credentials = utils.BytearrayStream(
            b'\x42\x00\x0C\x01\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 11.2.
        #
        # This encoding matches the following set of values:
        # Authentication
        #     Credential
        #         CredentialType - Device
        #         CredentialValue
        #             Device Serial Number - serNum123456
        #             Password - secret
        #             Device Identifier - devID2233
        #             Network Identifier - netID9000
        #             Machine Identifier - machineID1
        #             Media Identifier - mediaID313
        self.device_encoding = utils.BytearrayStream(
            b'\x42\x00\x0C\x01\x00\x00\x00\xA8'
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

        # Encoding obtained from the KMIP 1.1 testing document, combining
        # encodings from Sections 11.1 and 11.2.
        #
        # This encoding matches the following set of values:
        # Authentication
        #     Credential
        #         CredentialType - Username and Password
        #         CredentialValue
        #             Username - Fred
        #             Password - password1
        #     Credential
        #         CredentialType - Device
        #         CredentialValue
        #             Device Serial Number - serNum123456
        #             Password - secret
        #             Device Identifier - devID2233
        #             Network Identifier - netID9000
        #             Machine Identifier - machineID1
        #             Media Identifier - mediaID313
        self.multiple_credentials_encoding = utils.BytearrayStream(
            b'\x42\x00\x0C\x01\x00\x00\x00\xF0'
            b'\x42\x00\x23\x01\x00\x00\x00\x40'
            b'\x42\x00\x24\x05\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00'
            b'\x42\x00\x25\x01\x00\x00\x00\x28'
            b'\x42\x00\x99\x07\x00\x00\x00\x04'
            b'\x46\x72\x65\x64\x00\x00\x00\x00'
            b'\x42\x00\xA1\x07\x00\x00\x00\x09'
            b'\x70\x61\x73\x73\x77\x6F\x72\x64\x31\x00\x00\x00\x00\x00\x00\x00'
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
        super(TestAuthentication, self).tearDown()

    def test_init(self):
        """
        Test that an Authentication struct can be constructed without
        arguments.
        """
        authentication = contents.Authentication()

        self.assertEqual([], authentication.credentials)

    def test_init_with_args(self):
        """
        Test that an Authentication struct can be constructed with arguments.
        """
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="John",
                        password="abc123"
                    )
                )
            ]
        )

        self.assertEqual(1, len(authentication.credentials))
        self.assertEqual(
            objects.Credential(
                credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                credential_value=objects.UsernamePasswordCredential(
                    username="John",
                    password="abc123"
                )
            ),
            authentication.credentials[0]
        )

    def test_invalid_credentials(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the credentials of an Authentication struct.
        """
        kwargs = {'credentials': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Credentials must be a list of Credential structs.",
            contents.Authentication,
            **kwargs
        )

        authentication = contents.Authentication()
        args = (authentication, "credentials", 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Credentials must be a list of Credential structs.",
            setattr,
            *args
        )

    def test_invalid_credentials_list(self):
        """
        Test that a TypeError is raised when an invalid list is used to set
        the credentials of an Authentication struct.
        """
        kwargs = {
            'credentials': [
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="John",
                        password="abc123"
                    )
                ),
                'invalid'
            ]
        }
        self.assertRaisesRegex(
            TypeError,
            "Credentials must be a list of Credential structs. Item 2 has "
            "type: {}".format(type('invalid')),
            contents.Authentication,
            **kwargs
        )

        authentication = contents.Authentication()
        args = (
            authentication,
            "credentials",
            [
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="John",
                        password="abc123"
                    )
                ),
                'invalid'
            ]
        )
        self.assertRaisesRegex(
            TypeError,
            "Credentials must be a list of Credential structs. Item 2 has "
            "type: {}".format(type('invalid')),
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that an Authentication struct can be read from a data stream.
        """
        # Test with a single UsernamePasswordCredential.
        authentication = contents.Authentication()

        self.assertEqual([], authentication.credentials)

        authentication.read(self.username_password_encoding)

        self.assertEqual(1, len(authentication.credentials))
        self.assertEqual(
            objects.Credential(
                credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                credential_value=objects.UsernamePasswordCredential(
                    username="Fred",
                    password="password1"
                )
            ),
            authentication.credentials[0]
        )

        # Test with a single DeviceCredential.
        authentication = contents.Authentication()

        self.assertEqual([], authentication.credentials)

        authentication.read(self.device_encoding)

        self.assertEqual(1, len(authentication.credentials))
        self.assertEqual(
            objects.Credential(
                credential_type=enums.CredentialType.DEVICE,
                credential_value=objects.DeviceCredential(
                    device_serial_number="serNum123456",
                    password="secret",
                    device_identifier="devID2233",
                    network_identifier="netID9000",
                    machine_identifier="machineID1",
                    media_identifier="mediaID313"
                )
            ),
            authentication.credentials[0]
        )

        # Test with multiple Credentials.
        authentication = contents.Authentication()

        self.assertEqual([], authentication.credentials)

        authentication.read(self.multiple_credentials_encoding)

        self.assertEqual(2, len(authentication.credentials))
        self.assertEqual(
            objects.Credential(
                credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                credential_value=objects.UsernamePasswordCredential(
                    username="Fred",
                    password="password1"
                )
            ),
            authentication.credentials[0]
        )
        self.assertEqual(
            objects.Credential(
                credential_type=enums.CredentialType.DEVICE,
                credential_value=objects.DeviceCredential(
                    device_serial_number="serNum123456",
                    password="secret",
                    device_identifier="devID2233",
                    network_identifier="netID9000",
                    machine_identifier="machineID1",
                    media_identifier="mediaID313"
                )
            ),
            authentication.credentials[1]
        )

    def test_read_missing_credentials(self):
        """
        Test that a ValueError gets raised when attempting to read an
        Authentication struct from a data stream missing credentials data.
        """
        authentication = contents.Authentication()

        self.assertEqual([], authentication.credentials)

        args = (self.encoding_missing_credentials, )
        self.assertRaisesRegex(
            ValueError,
            "Authentication encoding missing credentials.",
            authentication.read,
            *args
        )

    def test_write(self):
        """
        Test that an Authentication struct can be written to a data stream.
        """
        # Test with a single UsernamePasswordCredential.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )
        stream = utils.BytearrayStream()

        authentication.write(stream)

        self.assertEqual(len(self.username_password_encoding), len(stream))
        self.assertEqual(str(self.username_password_encoding), str(stream))

        # Test with a single DeviceCredential.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )
        stream = utils.BytearrayStream()

        authentication.write(stream)

        self.assertEqual(len(self.device_encoding), len(stream))
        self.assertEqual(str(self.device_encoding), str(stream))

        # Test with multiple Credentials.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                ),
                objects.Credential(
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
            ]
        )
        stream = utils.BytearrayStream()

        authentication.write(stream)

        self.assertEqual(len(self.multiple_credentials_encoding), len(stream))
        self.assertEqual(str(self.multiple_credentials_encoding), str(stream))

    def test_write_missing_credentials(self):
        """
        Test that a ValueError gets raised when attempting to write a
        Authentication struct missing credentials data to a data stream.
        """
        authentication = contents.Authentication()
        stream = utils.BytearrayStream()

        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "Authentication struct missing credentials.",
            authentication.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        Authentication structs with the same data.
        """
        a = contents.Authentication()
        b = contents.Authentication()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        # Test with a single UsernamePasswordCredential.
        a = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        # Test with a single DeviceCredential.
        a = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        # Test with multiple Credentials.
        a = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                ),
                objects.Credential(
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
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                ),
                objects.Credential(
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
            ]
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_credentials(self):
        """
        Test that the equality operator returns False when comparing two
        Authentication structs with different credentials.
        """
        a = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two
        Authentication structs with different types.
        """
        a = contents.Authentication()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Authentication structs with the same data.
        """
        a = contents.Authentication()
        b = contents.Authentication()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        # Test with a single UsernamePasswordCredential.
        a = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        # Test with a single DeviceCredential.
        a = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        # Test with multiple Credentials.
        a = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                ),
                objects.Credential(
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
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                ),
                objects.Credential(
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
            ]
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_credentials(self):
        """
        Test that the inequality operator returns True when comparing two
        Authentication structs with different credentials.
        """
        a = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )
        b = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two
        Authentication structs with different types.
        """
        a = contents.Authentication()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to an Authentication struct.
        """
        # Test with a UsernamePasswordCredential.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )
        expected = (
            "Authentication("
            "credentials=["
            "Credential("
            "credential_type=CredentialType.USERNAME_AND_PASSWORD, "
            "credential_value=UsernamePasswordCredential("
            "username='Fred', "
            "password='password1'))])"
        )
        observed = repr(authentication)

        self.assertEqual(expected, observed)

        # Test with a DeviceCredential.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )
        expected = (
            "Authentication("
            "credentials=["
            "Credential("
            "credential_type=CredentialType.DEVICE, "
            "credential_value=DeviceCredential("
            "device_serial_number='serNum123456', "
            "password='secret', "
            "device_identifier='devID2233', "
            "network_identifier='netID9000', "
            "machine_identifier='machineID1', "
            "media_identifier='mediaID313'))])"
        )
        observed = repr(authentication)

        self.assertEqual(expected, observed)

        # Test with multiple Credentials.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                ),
                objects.Credential(
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
            ]
        )
        expected = (
            "Authentication("
            "credentials=["
            "Credential("
            "credential_type=CredentialType.USERNAME_AND_PASSWORD, "
            "credential_value=UsernamePasswordCredential("
            "username='Fred', "
            "password='password1')), "
            "Credential("
            "credential_type=CredentialType.DEVICE, "
            "credential_value=DeviceCredential("
            "device_serial_number='serNum123456', "
            "password='secret', "
            "device_identifier='devID2233', "
            "network_identifier='netID9000', "
            "machine_identifier='machineID1', "
            "media_identifier='mediaID313'))])"
        )
        observed = repr(authentication)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an Authentication struct.
        """
        # Test with a UsernamePasswordCredential.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                )
            ]
        )
        expected = str({
            "credentials": [
                {
                    "credential_type":
                        enums.CredentialType.USERNAME_AND_PASSWORD,
                    "credential_value": str({
                        "username": "Fred",
                        "password": "password1"
                    })
                }
            ]
        })
        observed = str(authentication)

        self.assertEqual(expected, observed)

        # Test with a DeviceCredential.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
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
            ]
        )
        expected = str({
            "credentials": [
                {
                    "credential_type": enums.CredentialType.DEVICE,
                    "credential_value": str({
                        "device_serial_number": "serNum123456",
                        "password": "secret",
                        "device_identifier": "devID2233",
                        "network_identifier": "netID9000",
                        "machine_identifier": "machineID1",
                        "media_identifier": "mediaID313"
                    })
                }
            ]
        })
        observed = str(authentication)

        self.assertEqual(expected, observed)

        # Test with multiple Credentials.
        authentication = contents.Authentication(
            credentials=[
                objects.Credential(
                    credential_type=enums.CredentialType.USERNAME_AND_PASSWORD,
                    credential_value=objects.UsernamePasswordCredential(
                        username="Fred",
                        password="password1"
                    )
                ),
                objects.Credential(
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
            ]
        )
        expected = str({
            "credentials": [
                {
                    "credential_type":
                        enums.CredentialType.USERNAME_AND_PASSWORD,
                    "credential_value": str({
                        "username": "Fred",
                        "password": "password1"
                    })
                },
                {
                    "credential_type": enums.CredentialType.DEVICE,
                    "credential_value": str({
                        "device_serial_number": "serNum123456",
                        "password": "secret",
                        "device_identifier": "devID2233",
                        "network_identifier": "netID9000",
                        "machine_identifier": "machineID1",
                        "media_identifier": "mediaID313"
                    })
                }
            ]
        })
        observed = str(authentication)

        self.assertEqual(expected, observed)
