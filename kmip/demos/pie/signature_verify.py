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
from kmip.pie import objects

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.SIGNATURE_VERIFY)
    opts, args = parser.parse_args(sys.argv[1:])
    config = opts.config

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        # Create keys to use for derivation
        try:
            signing_key_id = client.register(
                objects.PublicKey(
                    enums.CryptographicAlgorithm.RSA,
                    1120,
                    (
                        b'\x30\x81\x89\x02\x81\x81\x00\xac\x13\xd9\xfd\xae\x7b'
                        b'\x73\x35\xb6\x9c\xd9\x85\x67\xe9\x64\x7d\x99\xbf\x37'
                        b'\x3a\x9e\x05\xce\x34\x35\xd6\x64\x65\xf3\x28\xb7\xf7'
                        b'\x33\x4b\x79\x2a\xee\x7e\xfa\x04\x4e\xbc\x4c\x7a\x30'
                        b'\xb2\x1a\x5d\x7a\x89\xcd\xb3\xa3\x0d\xfc\xd9\xfe\xe9'
                        b'\x99\x5e\x09\x41\x5e\xdc\x0b\xf9\xe5\xb4\xc3\xf7\x4f'
                        b'\xf5\x3f\xb4\xd2\x94\x41\xbf\x1b\x7e\xd6\xcb\xdd\x4a'
                        b'\x47\xf9\x25\x22\x69\xe1\x64\x6f\x6c\x1a\xee\x05\x14'
                        b'\xe9\x3f\x6c\xb9\xdf\x71\xd0\x6c\x06\x0a\x21\x04\xb4'
                        b'\x7b\x72\x60\xac\x37\xc1\x06\x86\x1d\xc7\x8c\xa5\xa2'
                        b'\x5f\xaa\x9c\xb2\xe3\x02\x03\x01\x00\x01'
                    ),
                    masks=[
                        enums.CryptographicUsageMask.SIGN,
                        enums.CryptographicUsageMask.VERIFY
                    ]
                )
            )
            logger.info("Successfully created a new signing key.")
            logger.info("Signing Key ID: {0}".format(signing_key_id))
        except Exception as e:
            logger.error(e)
            sys.exit(-1)

        # Activate the signing key.
        try:
            client.activate(signing_key_id)
            logger.info(
                "Signing key {0} has been activated.".format(signing_key_id)
            )
        except Exception as e:
            logger.error(e)
            sys.exit(-1)

        # Verify a valid signature.
        try:
            result = client.signature_verify(
                (
                    b'\xe1\xc0\xf9\x8d\x53\xf8\xf8\xb1\x41\x90\x57\xd5\xb9\xb1'
                    b'\x0b\x07\xfe\xea\xec\x32\xc0\x46\x3a\x4d\x68\x38\x2f\x53'
                    b'\x1b\xa1\xd6\xcf\xe4\xed\x38\xa2\x69\x4a\x34\xb9\xc8\x05'
                    b'\xad\xf0\x72\xff\xbc\xeb\xe2\x1d\x8d\x4b\x5c\x0e\x8c\x33'
                    b'\x45\x2d\xd8\xf9\xc9\xbf\x45\xd1\xe6\x33\x75\x11\x33\x58'
                    b'\x82\x29\xd2\x93\xc6\x49\x6b\x7c\x98\x3c\x2c\x72\xbd\x21'
                    b'\xd3\x39\x27\x2d\x78\x28\xb0\xd0\x9d\x01\x0b\xba\xd3\x18'
                    b'\xd9\x98\xf7\x04\x79\x67\x33\x8a\xce\xfd\x01\xe8\x74\xac'
                    b'\xe5\xf8\x6d\x2a\x60\xf3\xb3\xca\xe1\x3f\xc5\xc6\x65\x08'
                    b'\xcf\xb7\x23\x78\xfd\xd6\xc8\xde\x24\x97\x65\x10\x3c\xe8'
                    b'\xfe\x7c\xd3\x3a\xd0\xef\x16\x86\xfe\xb2\x5e\x6a\x35\xfb'
                    b'\x64\xe0\x96\xa4'
                ),
                (
                    b'\x01\xf6\xe5\xff\x04\x22\x1a\xdc\x6c\x2f\x22\xa7\x61\x05'
                    b'\x3b\xc4\x73\x27\x65\xdd\xdc\x3f\x76\x56\xd0\xd1\x22\xad'
                    b'\x3b\x8a\x4e\x4f\x8f\xe5\x5b\xd0\xc0\x9e\xb1\x07\x80\xa1'
                    b'\x39\xcd\xa9\x32\x34\xef\x98\x8f\xe2\x50\x20\x1e\xb2\xfe'
                    b'\xbd\x08\xb6\xee\x85\xd7\x0d\x16\x05\xa5\xba\x56\x85\x21'
                    b'\x52\x99\xf0\x74\xc8\x0b\xaf\xf8\x1e\x2c\xa3\x10\x7d\xa9'
                    b'\x17\x5c\x2f\x5a\x7c\x6b\x60\xea\xa2\x8a\x75\x8c\xa9\x34'
                    b'\xf2\xff\x16\x98\x8f\xe8\x5f\xf8\x41\x57\xd9\x51\x44\x8a'
                    b'\x85\xec\x1e\xd1\x71\xf9\xef\x8b\xb8\xa1\x0c\xfa\x14\x7b'
                    b'\x7e\xf8'
                ),
                uid=signing_key_id,
                cryptographic_parameters={
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.RSA,
                    'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
                    'padding_method': enums.PaddingMethod.PSS
                },
            )
            if result == enums.ValidityIndicator.VALID:
                logger.info("Example 1: The signature is valid.")
            elif result == enums.ValidityIndicator.INVALID:
                logger.info("Example 1: The signature is invalid.")
            else:
                logger.info(
                    "Example 1: The signature validity is undetermined."
                )
        except Exception as e:
            logger.error(e)

        # Verify an invalid signature.
        try:
            result = client.signature_verify(
                b'This message is invalid.',
                (
                    b'\x01\xf6\xe5\xff\x04\x22\x1a\xdc\x6c\x2f\x22\xa7\x61\x05'
                    b'\x3b\xc4\x73\x27\x65\xdd\xdc\x3f\x76\x56\xd0\xd1\x22\xad'
                    b'\x3b\x8a\x4e\x4f\x8f\xe5\x5b\xd0\xc0\x9e\xb1\x07\x80\xa1'
                    b'\x39\xcd\xa9\x32\x34\xef\x98\x8f\xe2\x50\x20\x1e\xb2\xfe'
                    b'\xbd\x08\xb6\xee\x85\xd7\x0d\x16\x05\xa5\xba\x56\x85\x21'
                    b'\x52\x99\xf0\x74\xc8\x0b\xaf\xf8\x1e\x2c\xa3\x10\x7d\xa9'
                    b'\x17\x5c\x2f\x5a\x7c\x6b\x60\xea\xa2\x8a\x75\x8c\xa9\x34'
                    b'\xf2\xff\x16\x98\x8f\xe8\x5f\xf8\x41\x57\xd9\x51\x44\x8a'
                    b'\x85\xec\x1e\xd1\x71\xf9\xef\x8b\xb8\xa1\x0c\xfa\x14\x7b'
                    b'\x7e\xf8'
                ),
                uid=signing_key_id,
                cryptographic_parameters={
                    'cryptographic_algorithm':
                        enums.CryptographicAlgorithm.RSA,
                    'hashing_algorithm': enums.HashingAlgorithm.SHA_1,
                    'padding_method': enums.PaddingMethod.PSS
                },
            )
            if result == enums.ValidityIndicator.VALID:
                logger.info("Example 2: The signature is valid.")
            elif result == enums.ValidityIndicator.INVALID:
                logger.info("Example 2: The signature is invalid.")
            else:
                logger.info(
                    "Example 2: The signature validity is undetermined."
                )
        except Exception as e:
            logger.error(e)
