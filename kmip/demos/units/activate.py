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

from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus

from kmip.demos import utils

from kmip.services.kmip_client import KMIPProxy

import logging
import sys

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.ACTIVATE)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    uuid = opts.uuid

    # Exit early if the UUID is not specified
    if uuid is None:
        logger.error('No UUID provided, exiting early from demo')
        sys.exit()

    # Build the client and connect to the server
    client = KMIPProxy(config=config, config_file=opts.config_file)
    client.open()

    # Activate the object
    result = client.activate(uuid)
    client.close()

    # Display operation results
    logger.info('activate() result status: {0}'.format(
        result.result_status.value))

    if result.result_status.value == ResultStatus.SUCCESS:
        logger.info('activated UUID: {0}'.format(result.uuid.value))
    else:
        logger.info('activate() result reason: {0}'.format(
            result.result_reason.value))
        logger.info('activate() result message: {0}'.format(
            result.result_message.value))
