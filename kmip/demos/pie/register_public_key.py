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

import logging
import sys

from kmip.core import enums
from kmip.demos import utils

from kmip.pie import client
from kmip.pie import objects

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    parser = utils.build_cli_parser(enums.Operation.REGISTER)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config

    algorithm = enums.CryptographicAlgorithm.RSA
    length = 2048
    value = (
        b'\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42\x49'
        b'\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00\x3A'
        b'\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00\x2C'
        b'\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D\x75'
        b'\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7\xEC'
        b'\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F\xA2'
        b'\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4\xBB'
        b'\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF\x8B'
        b'\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D\x57'
        b'\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC\xC8'
        b'\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7\xF4'
        b'\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D\x0C'
        b'\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE\x64'
        b'\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC\xE8'
        b'\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73\xA1'
        b'\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC\x41'
        b'\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01')
    format_type = enums.KeyFormatType.X_509
    usage_mask = [enums.CryptographicUsageMask.VERIFY]
    name = 'Demo Public Key'

    key = objects.PublicKey(
        algorithm, length, value, format_type, usage_mask, name)
    key.operation_policy_name = opts.operation_policy_name

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        try:
            uid = client.register(key)
            logger.info("Successfully registered public key with ID: "
                        "{0}".format(uid))
        except Exception as e:
            logger.error(e)
