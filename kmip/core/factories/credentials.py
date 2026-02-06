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

from kmip.core import enums
from kmip.core import objects

class CredentialFactory(object):

    def create_credential(self, credential_type, credential_value):
        # Switch on the type of the credential
        if credential_type is enums.CredentialType.USERNAME_AND_PASSWORD:
            credential_value = self.create_username_password_credential(
                credential_value
            )
        elif credential_type is enums.CredentialType.DEVICE:
            credential_value = self.create_device_credential(credential_value)
        else:
            msg = 'Unrecognized credential type: {0}'
            raise ValueError(msg.format(credential_type))

        return objects.Credential(
            credential_type=credential_type,
            credential_value=credential_value
        )

    @staticmethod
    def create_username_password_credential(value):
        username = value.get('Username')
        password = value.get('Password')

        return objects.UsernamePasswordCredential(
            username=username,
            password=password
        )

    @staticmethod
    def create_device_credential(value):
        dsn = value.get('Device Serial Number')
        password = value.get('Password')
        dev_id = value.get('Device Identifier')
        net_id = value.get('Network Identifier')
        mach_id = value.get('Machine Identifier')
        med_id = value.get('Media Identifier')

        return objects.DeviceCredential(
            device_serial_number=dsn,
            password=password,
            device_identifier=dev_id,
            network_identifier=net_id,
            machine_identifier=mach_id,
            media_identifier=med_id
        )
