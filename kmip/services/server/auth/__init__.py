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

from kmip.services.server.auth.api import AuthAPI
from kmip.services.server.auth.slugs import SLUGSConnector

from kmip.services.server.auth.utils import get_certificate_from_connection
from kmip.services.server.auth.utils import \
    get_client_identity_from_certificate
from kmip.services.server.auth.utils import get_common_names_from_certificate
from kmip.services.server.auth.utils import \
    get_extended_key_usage_from_certificate

__all__ = [
    'AuthAPI',
    'SLUGSConnector',
    'get_certificate_from_connection',
    'get_client_identity_from_certificate',
    'get_common_names_from_certificate',
    'get_extended_key_usage_from_certificate'
]
