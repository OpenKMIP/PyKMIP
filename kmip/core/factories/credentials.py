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

from kmip.core.enums import CredentialType

from kmip.core.objects import Credential


class CredentialFactory(object):
    def __init__(self):
        pass

    def _create_credential(self, credential_type, credential_value):
        credential_type = Credential.CredentialType(credential_type)
        return Credential(credential_type=credential_type,
                          credential_value=credential_value)

    def create_credential(self, cred_type, value):
        # Switch on the type of the credential
        if cred_type is CredentialType.USERNAME_AND_PASSWORD:
            value = self._create_username_password_credential(value)
        elif cred_type is CredentialType.DEVICE:
            value = self._create_device_credential(value)
        else:
            msg = 'Unrecognized credential type: {0}'
            raise ValueError(msg.format(cred_type))

        return self._create_credential(cred_type, value)

    def _create_username_password_credential(self, value):
        username = value.get('Username')
        password = value.get('Password')

        username = Credential.UsernamePasswordCredential.Username(username)
        password = Credential.UsernamePasswordCredential.Password(password)

        return Credential.UsernamePasswordCredential(username=username,
                                                     password=password)

    def _create_device_credential(self, value):
        dsn = value.get('Device Serial Number')
        password = value.get('Password')
        dev_id = value.get('Device Identifier')
        net_id = value.get('Network Identifier')
        mach_id = value.get('Machine Identifier')
        med_id = value.get('Media Identifier')

        dsn = Credential.DeviceCredential.DeviceSerialNumber(dsn)
        password = Credential.DeviceCredential.Password(password)
        dev_id = Credential.DeviceCredential.DeviceIdentifier(dev_id)
        net_id = Credential.DeviceCredential.NetworkIdentifier(net_id)
        mach_id = Credential.DeviceCredential.MachineIdentifier(mach_id)
        med_id = Credential.DeviceCredential.MediaIdentifier(med_id)

        return Credential.DeviceCredential(device_serial_number=dsn,
                                           password=password,
                                           device_identifier=dev_id,
                                           network_identifier=net_id,
                                           machine_identifier=mach_id,
                                           media_identifier=med_id)
