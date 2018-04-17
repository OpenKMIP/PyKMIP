# Copyright (c) 2017 Pure Storage, Inc. All Rights Reserved.
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

from kmip.core.enums import NameType
from kmip.core.enums import Operation

from kmip.core.attributes import Name

from kmip.core.objects import Attribute

from kmip.demos import utils

from kmip.pie import client

import logging
import sys


if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.LOCATE)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    name = opts.name

    # Exit early if name is not specified
    if name is None:
        logger.error('No name provided, exiting early from demo')
        sys.exit()

    # Build name attribute
    # TODO Push this into the AttributeFactory
    attribute_name = Attribute.AttributeName('Name')
    name_value = Name.NameValue(name)
    name_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
    value = Name.create(name_value=name_value, name_type=name_type)
    name_obj = Attribute(attribute_name=attribute_name, attribute_value=value)
    attributes = [name_obj]

    # Build the client and connect to the server
    with client.ProxyKmipClient(
            config=config,
            config_file=opts.config_file
    ) as client:
        try:
            uuids = client.locate(attributes=attributes)
            logger.info("Located uuids: {0}".format(uuids))
        except Exception as e:
            logger.error(e)
