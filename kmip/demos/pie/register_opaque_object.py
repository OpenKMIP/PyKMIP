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

    value = b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64'
    opaque_type = enums.OpaqueDataType.NONE
    name = 'Demo Opaque Object'

    obj = objects.OpaqueObject(value, opaque_type, name)
    obj.operation_policy_name = opts.operation_policy_name

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        try:
            uid = client.register(obj)
            logger.info("Successfully registered opaque object with ID: "
                        "{0}".format(uid))
        except Exception as e:
            logger.error(e)
