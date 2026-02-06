# Copyright (c) 2014 The Johns Hopkins University/Applied Physics Laboratory
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

import os
import re

from kmip.core import enums
from kmip.pie import client
from kmip.pie import objects
from kmip.pie.client import ProxyKmipClient as KmipClient

# Dynamically set __version__
version_path = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "version.py"
)
with open(version_path, 'r') as f:
    m = re.search(
        r"^__version__ = \"(\d+\.\d+\..*)\"$",
        f.read(),
        re.MULTILINE
    )
    __version__ = m.group(1)

__all__ = [
    'client',
    'core',
    'demos',
    'enums',
    'KmipClient',
    'objects',
    'services'
]
