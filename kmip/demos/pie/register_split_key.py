# Copyright (c) 2019 The Johns Hopkins University/Applied Physics Laboratory
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

    split_key = objects.SplitKey(
        cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
        cryptographic_length=128,
        key_value=(
            b'\x66\xC4\x6A\x77\x54\xF9\x4D\xE4'
            b'\x20\xC7\xB1\xA7\xFF\xF5\xEC\x56'
        ),
        name="Demo Split Key",
        cryptographic_usage_masks=[enums.CryptographicUsageMask.EXPORT],
        key_format_type=enums.KeyFormatType.RAW,
        key_wrapping_data=None,
        split_key_parts=4,
        key_part_identifier=1,
        split_key_threshold=2,
        split_key_method=enums.SplitKeyMethod.XOR,
        prime_field_size=None
    )
    split_key.operation_policy_name = opts.operation_policy_name

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        try:
            uid = client.register(split_key)
            logger.info(
                "Successfully registered split key with ID: {0}".format(uid)
            )
        except Exception as e:
            logger.error(e)
