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

from kmip.core.factories import attributes
from kmip.core import enums
from kmip.demos import utils

from kmip.pie import client

# NOTE: This demo script shows how to modify the first Name attribute on
# the user-specified object. The object *must* have at least one Name
# attribute for attribute modification to work. Otherwise, the client
# call to modify_attribute will fail.

if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    parser = utils.build_cli_parser(enums.Operation.MODIFY_ATTRIBUTE)
    opts, args = parser.parse_args(sys.argv[1:])

    if opts.uuid is None:
        logger.error("No UUID provided, existing early from demo.")
        sys.exit()

    factory = attributes.AttributeFactory()

    with client.ProxyKmipClient(
        config=opts.config,
        config_file=opts.config_file
    ) as c:
        try:
            object_id, modified_attribute = c.modify_attribute(
                unique_identifier=opts.uuid,
                attribute=factory.create_attribute(
                    enums.AttributeType.NAME,
                    "Modified Name",
                    index=0
                )
            )
            logger.info(
                "Successfully modified 'Name' attribute on object: {}".format(
                    object_id
                )
            )
            logger.info("Modified attribute: {}".format(modified_attribute))
        except Exception as e:
            logger.error(e)
