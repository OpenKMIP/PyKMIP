# Copyright (c) 2017 The Johns Hopkins University/Applied Physics Laboratory
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

import logging
import sys

from kmip.core import enums
from kmip.demos import utils
from kmip.pie import client

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.DERIVE_KEY)
    opts, args = parser.parse_args(sys.argv[1:])
    config = opts.config

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        # Create keys to use for derivation
        try:
            key_id = client.create(
                enums.CryptographicAlgorithm.AES,
                128,
                cryptographic_usage_mask=[
                    enums.CryptographicUsageMask.DERIVE_KEY
                ]
            )
            logger.info("Successfully created a new derivation key.")
            logger.info("Secret ID: {0}".format(key_id))
        except Exception as e:
            logger.error(e)
            sys.exit(-1)

        # Derive a new secret via PBKDF2.
        try:
            secret_id = client.derive_key(
                enums.ObjectType.SYMMETRIC_KEY,
                [key_id],
                enums.DerivationMethod.PBKDF2,
                {
                    'cryptographic_parameters': {
                        'hashing_algorithm': enums.HashingAlgorithm.SHA_1
                    },
                    'salt': b'salt',
                    'iteration_count': 4096
                },
                cryptographic_length=160,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES
            )
            logger.info("Successfully derived a new secret via PBKDF2.")
            logger.info("Secret ID: {0}".format(secret_id))
        except Exception as e:
            logger.error(e)

        # Derive a new secret via encryption.
        try:
            secret_id = client.derive_key(
                enums.ObjectType.SECRET_DATA,
                [key_id],
                enums.DerivationMethod.ENCRYPT,
                {
                    'cryptographic_parameters': {
                        'block_cipher_mode': enums.BlockCipherMode.CBC,
                        'padding_method': enums.PaddingMethod.PKCS5,
                        'cryptographic_algorithm':
                            enums.CryptographicAlgorithm.BLOWFISH
                    },
                    'initialization_vector': (
                        b'\xFE\xDC\xBA\x98\x76\x54\x32\x10'
                    ),
                    'derivation_data': (
                        b'\x37\x36\x35\x34\x33\x32\x31\x30'
                        b'\x4E\x6F\x77\x20\x69\x73\x20\x74'
                        b'\x68\x65\x20\x74\x69\x6D\x65\x20'
                        b'\x66\x6F\x72\x20\x00'
                    )
                },
                cryptographic_length=256
            )
            logger.info("Successfully derived a new secret via encryption.")
            logger.info("Secret ID: {0}".format(secret_id))
        except Exception as e:
            logger.error(e)

        # Derive a new secret via HMAC.
        try:
            secret_id = client.derive_key(
                enums.ObjectType.SYMMETRIC_KEY,
                [key_id],
                enums.DerivationMethod.HMAC,
                {
                    'cryptographic_parameters': {
                        'hashing_algorithm': enums.HashingAlgorithm.SHA_256
                    },
                    'derivation_data': (
                        b'\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7'
                        b'\xF8\xF9'
                    ),
                    'salt': (
                        b'\x00\x01\x02\x03\x04\x05\x06\x07'
                        b'\x08\x09\x0A\x0B\x0C'
                    )
                },
                cryptographic_length=64,
                cryptographic_algorithm=enums.CryptographicAlgorithm.RC4
            )
            logger.info("Successfully derived a new secret via HMAC.")
            logger.info("Secret ID: {0}".format(secret_id))
        except Exception as e:
            logger.error(e)

        # Derive a new secret via hashing.
        try:
            secret_id = client.derive_key(
                enums.ObjectType.SECRET_DATA,
                [key_id],
                enums.DerivationMethod.HASH,
                {
                    'cryptographic_parameters': {
                        'hashing_algorithm': enums.HashingAlgorithm.MD5
                    }
                },
                cryptographic_length=128
            )
            logger.info("Successfully derived a new secret via hashing.")
            logger.info("Secret ID: {0}".format(secret_id))
        except Exception as e:
            logger.error(e)

        # Derive a new secret via NIST 800 108-C.
        try:
            secret_id = client.derive_key(
                enums.ObjectType.SYMMETRIC_KEY,
                [key_id],
                enums.DerivationMethod.NIST800_108_C,
                {
                    'cryptographic_parameters': {
                        'hashing_algorithm': enums.HashingAlgorithm.SHA_1
                    },
                    'derivation_data': (
                        b'\x8e\x34\x7e\xf5\x5d\x5f\x5e\x99'
                        b'\xea\xb6\xde\x70\x6b\x51\xde\x7c'
                        b'\xe0\x04\xf3\x88\x28\x89\xe2\x59'
                        b'\xff\x4e\x5c\xff\x10\x21\x67\xa5'
                        b'\xa4\xbd\x71\x15\x78\xd4\xce\x17'
                        b'\xdd\x9a\xbe\x56\xe5\x1c\x1f\x2d'
                        b'\xf9\x50\xe2\xfc\x81\x2e\xc1\xb2'
                        b'\x17\xca\x08\xd6'
                    )
                },
                cryptographic_length=128,
                cryptographic_algorithm=enums.CryptographicAlgorithm.AES
            )
            logger.info(
                "Successfully derived a new secret via NIST 800 108-C."
            )
            logger.info("Secret ID: {0}".format(secret_id))
        except Exception as e:
            logger.error(e)
