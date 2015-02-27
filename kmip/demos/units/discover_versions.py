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
import os
import sys


if __name__ == '__main__':
    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.DISCOVER_VERSIONS)
    opts, args = parser.parse_args(sys.argv[1:])

    username = opts.username
    password = opts.password
    config = opts.config

    # Build and setup logging
    f_log = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                         'logconfig.ini')
    logging.config.fileConfig(f_log)
    logger = logging.getLogger(__name__)

    # Build the client and connect to the server
    client = KMIPProxy(config=config)
    client.open()

    result = client.discover_versions()
    client.close()

    # Display operation results
    logger.debug('discover_versions() result status: {0}'.format(
        result.result_status.enum))

    if result.result_status.enum == ResultStatus.SUCCESS:
        protocol_versions = result.protocol_versions
        if isinstance(protocol_versions, list):
            logger.debug('number of protocol versions returned: {0}'.format(
                len(protocol_versions)))
            for protocol_version in protocol_versions:
                logging.debug('protocol version supported: {0}'.format(
                    protocol_version))
        else:
            logger.debug('number of protocol versions returned: 0')
    else:
        logger.debug('discover_versions() result reason: {0}'.format(
            result.result_reason.enum))
        logger.debug('discover_versions() result message: {0}'.format(
            result.result_message.value))
