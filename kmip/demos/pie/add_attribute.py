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
    parser = utils.build_cli_parser(enums.Operation.ADD_ATTRIBUTE)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    uid = opts.uuid
    attribute_type = opts.attribute_type
    attribute_sub_type = opts.attribute_sub_type
    attribute_value = opts.attribute_value

    if attribute_type not in enums.AttributeType.__members__:
        logger.error("Invalid AttributeType provided: {0}".format(
            attribute_type))
        sys.exit()
    else:
        attribute_type = enums.AttributeType[attribute_type]

    if attribute_type == enums.AttributeType.LINK:
        if attribute_sub_type not in enums.LinkType.__members__:
            logger.error("Invalid LinkType provided: {0}".format(
                attribute_sub_type))
            sys.exit()
        else:
            attribute_sub_type = enums.LinkType[attribute_sub_type]

    # Exit early if the UUID is not specified
    if uid is None:
        logger.error('No ID provided, exiting early from demo')
        sys.exit()

    if attribute_type is None:
        logger.error('No Attribute Type provided, exiting early from demo')
        sys.exit()

    attribute_value_list = list()
    if attribute_sub_type is not None:
        attribute_value_list.append(attribute_sub_type)
    attribute_value_list.append(attribute_value)

    # Build the client and connect to the server
    with client.ProxyKmipClient(config=config) as client:
        try:
            uid, attribute = client.add_attribute(
                uid,
                attribute_type,
                attribute_value_list)
            logger.info("Successfully added {0} to object {1}".format(
                repr(attribute.attribute_value),
                uid))
        except Exception as e:
            logger.error(e)
