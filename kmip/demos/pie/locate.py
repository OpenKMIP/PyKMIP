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

import calendar
import logging
import sys
import time

from kmip.core import enums
from kmip.core.factories.attributes import AttributeFactory
from kmip.demos import utils
from kmip.pie import client


if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(enums.Operation.LOCATE)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    name = opts.name
    initial_dates = opts.initial_dates

    attribute_factory = AttributeFactory()

    # Build attributes if any are specified
    attributes = []
    if name:
        attributes.append(
            attribute_factory.create_attribute(enums.AttributeType.NAME, name)
        )
    for initial_date in initial_dates:
        try:
            t = time.strptime(initial_date)
        except ValueError, TypeError:
            logger.error(
                "Invalid initial date provided: {}".format(initial_date)
            )
            logger.info(
                "Date values should be formatted like this: "
                "'Tue Jul 23 18:39:01 2019'"
            )
            sys.exit(-1)

        try:
            t = calendar.timegm(t)
        except Exception:
            logger.error(
                "Failed to convert initial date time tuple "
                "to an integer: {}".format(t)
            )
            sys.exit(-2)

        attributes.append(
            attribute_factory.create_attribute(
                enums.AttributeType.INITIAL_DATE,
                t
            )
        )

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
