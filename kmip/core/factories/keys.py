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

from kmip.core.enums import KeyFormatType

from kmip.core.keys import ECPrivateKey
from kmip.core.keys import OpaqueKey
from kmip.core.keys import PKCS1Key
from kmip.core.keys import PKCS8Key
from kmip.core.keys import RawKey
from kmip.core.keys import TransparentSymmetricKey
from kmip.core.keys import X509Key


class KeyFactory(object):

    def create_key(self, key_format, value=None):
        if value is None:
            value = {}

        # Switch on the format type of the key
        if key_format is KeyFormatType.RAW:
            return self._create_raw_key(value)
        elif key_format is KeyFormatType.OPAQUE:
            return self._create_opaque_key()
        elif key_format is KeyFormatType.PKCS_1:
            return self._create_pkcs_1_key()
        elif key_format is KeyFormatType.PKCS_8:
            return self._create_pkcs_8_key()
        elif key_format is KeyFormatType.X_509:
            return self._create_x_509_key()
        elif key_format is KeyFormatType.EC_PRIVATE_KEY:
            return self._create_ec_private_key()
        elif key_format is KeyFormatType.TRANSPARENT_SYMMETRIC_KEY:
            return self._create_transparent_symmetric_key()
        elif key_format is KeyFormatType.TRANSPARENT_DSA_PRIVATE_KEY:
            return self._create_transparent_dsa_private_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_DSA_PUBLIC_KEY:
            return self._create_transparent_dsa_public_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_RSA_PRIVATE_KEY:
            return self._create_transparent_rsa_private_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_RSA_PUBLIC_KEY:
            return self._create_transparent_rsa_public_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_DH_PRIVATE_KEY:
            return self._create_transparent_dh_private_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_DH_PUBLIC_KEY:
            return self._create_transparent_dh_public_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_ECDSA_PRIVATE_KEY:
            return self._create_transparent_ecdsa_private_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_ECDSA_PUBLIC_KEY:
            return self._create_transparent_ecdsa_public_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_ECDH_PRIVATE_KEY:
            return self._create_transparent_ecdh_private_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_ECDH_PUBLIC_KEY:
            return self._create_transparent_ecdh_public_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_ECMQV_PRIVATE_KEY:
            return self._create_transparent_ecmqv_private_key(value)
        elif key_format is KeyFormatType.TRANSPARENT_ECMQV_PUBLIC_KEY:
            return self._create_transparent_ecmqv_public_key(value)
        else:
            msg = 'Unrecognized key format type: {0}'
            raise ValueError(msg.format(key_format))

    def _create_raw_key(self, value):
        data = value.get('bytes')
        return RawKey(data)

    def _create_opaque_key(self):
        return OpaqueKey()

    def _create_pkcs_1_key(self):
        return PKCS1Key()

    def _create_pkcs_8_key(self):
        return PKCS8Key()

    def _create_x_509_key(self):
        return X509Key()

    def _create_ec_private_key(self):
        return ECPrivateKey()

    def _create_transparent_symmetric_key(self):
        return TransparentSymmetricKey()

    def _create_transparent_dsa_private_key(self, value):
        raise NotImplementedError()

    def _create_transparent_dsa_public_key(self, value):
        raise NotImplementedError()

    def _create_transparent_rsa_private_key(self, value):
        raise NotImplementedError()

    def _create_transparent_rsa_public_key(self, value):
        raise NotImplementedError()

    def _create_transparent_dh_private_key(self, value):
        raise NotImplementedError()

    def _create_transparent_dh_public_key(self, value):
        raise NotImplementedError()

    def _create_transparent_ecdsa_private_key(self, value):
        raise NotImplementedError()

    def _create_transparent_ecdsa_public_key(self, value):
        raise NotImplementedError()

    def _create_transparent_ecdh_private_key(self, value):
        raise NotImplementedError()

    def _create_transparent_ecdh_public_key(self, value):
        raise NotImplementedError()

    def _create_transparent_ecmqv_private_key(self, value):
        raise NotImplementedError()

    def _create_transparent_ecmqv_public_key(self, value):
        raise NotImplementedError()
