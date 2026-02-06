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

from kmip.core import enums
from kmip.core import primitives

class RequestPayload(primitives.Struct):
    """
    An abstract base class for KMIP request payloads.
    """
    def __init__(self):
        super(RequestPayload, self).__init__(enums.Tags.REQUEST_PAYLOAD)

class ResponsePayload(primitives.Struct):
    """
    An abstract base class for KMIP response payloads.
    """

    def __init__(self):
        super(ResponsePayload, self).__init__(enums.Tags.RESPONSE_PAYLOAD)
