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

from six.moves import xrange

from kmip.core.enums import Operation
from kmip.core.enums import QueryFunction as QueryFunctionEnum
from kmip.core.enums import ResultStatus

from kmip.core.misc import QueryFunction

from kmip.demos import utils

from kmip.services.kmip_client import KMIPProxy


if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.QUERY)
    opts, args = parser.parse_args(sys.argv[1:])

    username = opts.username
    password = opts.password
    config = opts.config

    # Build query function list.
    query_functions = list()
    query_functions.append(
        QueryFunction(QueryFunctionEnum.QUERY_OPERATIONS))
    query_functions.append(
        QueryFunction(QueryFunctionEnum.QUERY_OBJECTS))
    query_functions.append(
        QueryFunction(QueryFunctionEnum.QUERY_SERVER_INFORMATION))
    query_functions.append(
        QueryFunction(QueryFunctionEnum.QUERY_APPLICATION_NAMESPACES))
    query_functions.append(
        QueryFunction(QueryFunctionEnum.QUERY_EXTENSION_LIST))
    query_functions.append(
        QueryFunction(QueryFunctionEnum.QUERY_EXTENSION_MAP))

    # Build the client and connect to the server
    client = KMIPProxy(config=config)
    client.open()

    result = client.query(query_functions=query_functions)
    client.close()

    # Display operation results
    logger.info('query() result status: {0}'.format(
        result.result_status.value))

    if result.result_status.value == ResultStatus.SUCCESS:
        operations = result.operations
        object_types = result.object_types
        vendor_identification = result.vendor_identification
        server_information = result.server_information
        application_namespaces = result.application_namespaces
        extension_information = result.extension_information

        logger.info('number of operations supported: {0}'.format(
            len(operations)))
        for i in xrange(len(operations)):
            logger.info('operation supported: {0}'.format(operations[i]))

        logger.info('number of object types supported: {0}'.format(
            len(object_types)))
        for i in xrange(len(object_types)):
            logger.info('object type supported: {0}'.format(object_types[i]))

        logger.info('vendor identification: {0}'.format(vendor_identification))
        logger.info('server information: {0}'.format(server_information))

        logger.info('number of application namespaces supported: {0}'.format(
            len(application_namespaces)))
        for i in xrange(len(application_namespaces)):
            logger.info('application namespace supported: {0}'.format(
                application_namespaces[i]))

        logger.info('number of extensions supported: {0}'.format(
            len(extension_information)))
        for i in xrange(len(extension_information)):
            logger.info('extension supported: {0}'.format(
                extension_information[i]))

    else:
        logger.info('query() result reason: {0}'.format(
            result.result_reason.value))
        logger.info('query() result message: {0}'.format(
            result.result_message.value))
