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

from kmip.services import kmip_client
from kmip.pie import client as pclient

def pytest_addoption(parser):
    parser.addoption(
        "--config",
        action="store",
        default="client",
        help="Config file section name for client configuration settings")

@pytest.fixture(scope="class")
def client(request):
    config = request.config.getoption("--config")

    client = kmip_client.KMIPProxy(config=config)
    client.open()

    def finalize():
        client.close()

    request.addfinalizer(finalize)
    request.cls.client = client

@pytest.fixture(scope="class")
def simple(request):
    config = request.config.getoption("--config")

    client = pclient.ProxyKmipClient(config=config)
    client.open()

    def finalize():
        client.close()

    request.addfinalizer(finalize)
    request.cls.client = client
