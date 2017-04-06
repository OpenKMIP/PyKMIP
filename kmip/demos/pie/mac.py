# Copyright (c) 2017 Pure Storage, Inc. All Rights Reserved.
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
import binascii

from kmip.core import enums
from kmip.demos import utils

from kmip.pie import client


if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.MAC)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    uid = opts.uuid
    algorithm = opts.algorithm

    data = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
        b'\x0F')

    # Exit early if the arguments are not specified
    if uid is None:
        logger.error('No UUID provided, exiting early from demo')
        sys.exit()
    if algorithm is None:
        logger.error('No algorithm provided, exiting early from demo')
        sys.exit()

    algorithm = getattr(enums.CryptographicAlgorithm, algorithm, None)

    # Build the client and connect to the server
    with client.ProxyKmipClient(config=config) as client:
        try:
            uid, mac_data = client.mac(data, uid, algorithm)
            logger.info("Successfully done MAC using key with ID: "
                        "{0}".format(uid))
            logger.info("MACed data: {0}".format(
                str(binascii.hexlify(mac_data))))
        except Exception as e:
            logger.error(e)
