# Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
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

def pytest_addoption(parser):
    parser.addoption(
        "--config-file",
        action="store",
        help="Config file path for client configuration settings"
    )

@pytest.fixture(scope="class")
def config_file(request):
    request.cls.config_file = request.config.getoption("--config-file")
