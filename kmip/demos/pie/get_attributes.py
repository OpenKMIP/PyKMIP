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
    parser = utils.build_cli_parser(enums.Operation.GET_ATTRIBUTES)
    opts, args = parser.parse_args(sys.argv[1:])

    config = opts.config
    unique_identifier = opts.uuid

    attribute_names = []

    # Build the client and connect to the server
    with client.ProxyKmipClient(config=config) as client:
        try:
            retrieved_id, retrieved_attributes = client.get_attributes(
                unique_identifier,
                attribute_names
            )
            logger.info(
                "Successfully retrieved attributes for object: {0}".format(
                    retrieved_id
                )
            )
            logger.info(
                "Successfully retrieved {0} attributes:".format(
                    len(retrieved_attributes)
                )
            )
            for attribute in retrieved_attributes:
                logger.info("Attribute: {0}".format(attribute))
        except Exception as e:
            logger.error(e)
