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

from kmip.core.messages.contents import ProtocolVersion

from kmip.demos import utils

from kmip.services.kmip_client import KMIPProxy

import logging
import sys
import re

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.DISCOVER_VERSIONS)
    opts, args = parser.parse_args(sys.argv[1:])

    username = opts.username
    password = opts.password
    config = opts.config

    protocol_versions = list()
    if opts.protocol_versions is not None:
        for version in re.split(',| ', opts.protocol_versions):
            mm = re.split(r'\.', version)
            protocol_versions.append(ProtocolVersion(int(mm[0]), int(mm[1])))

    # Build the client and connect to the server
    client = KMIPProxy(config=config, config_file=opts.config_file)
    client.open()

    result = client.discover_versions(protocol_versions=protocol_versions)
    client.close()

    # Display operation results
    logger.info('discover_versions() result status: {0}'.format(
        result.result_status.value))

    if result.result_status.value == ResultStatus.SUCCESS:
        protocol_versions = result.protocol_versions
        if isinstance(protocol_versions, list):
            logger.info('number of protocol versions returned: {0}'.format(
                len(protocol_versions)))
            for protocol_version in protocol_versions:
                logger.info('protocol version supported: {0}'.format(
                            protocol_version))
        else:
            logger.info('number of protocol versions returned: 0')
    else:
        logger.info('discover_versions() result reason: {0}'.format(
            result.result_reason.value))
        logger.info('discover_versions() result message: {0}'.format(
            result.result_message.value))
