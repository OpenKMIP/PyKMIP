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

import pytest
from testtools import TestCase

from kmip.core.enums import ResultStatus
from kmip.core.enums import QueryFunction as QueryFunctionEnum

from kmip.core.misc import QueryFunction


@pytest.mark.usefixtures("client")
class TestIntegration(TestCase):

    def setUp(self):
        super(TestIntegration, self).setUp()

    def tearDown(self):
        super(TestIntegration, self).tearDown()

    def test_discover_versions(self):
        result = self.client.discover_versions()

        expected = ResultStatus.SUCCESS
        observed = result.result_status.enum

        self.assertEqual(expected, observed)

    def test_query(self):
        # Build query function list, asking for all server data.
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

        result = self.client.query(query_functions=query_functions)

        expected = ResultStatus.SUCCESS
        observed = result.result_status.enum

        self.assertEqual(expected, observed)
