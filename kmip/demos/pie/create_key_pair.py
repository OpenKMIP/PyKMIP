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

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.CREATE_KEY_PAIR)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    algorithm = opts.algorithm
    length = opts.length

    # Exit early if the arguments are not specified
    if algorithm is None:
        logger.error('No algorithm provided, exiting early from demo')
        sys.exit()
    if length is None:
        logger.error("No key length provided, exiting early from demo")
        sys.exit()

    algorithm = getattr(enums.CryptographicAlgorithm, algorithm, None)

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        try:
            public_uid, private_uid = client.create_key_pair(
                algorithm,
                length,
                operation_policy_name=opts.operation_policy_name,
                public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
                private_usage_mask=[enums.CryptographicUsageMask.SIGN]
            )
            logger.info("Successfully created public key with ID: {0}".format(
                public_uid))
            logger.info("Successfully created private key with ID: {0}".format(
                private_uid))
        except Exception as e:
            logger.error(e)
