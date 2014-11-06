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

__all__ = ['create', 'destroy', 'get', 'locate', 'register']

from kmip.core import enums

from kmip.core.messages.payloads import create
from kmip.core.messages.payloads import get
from kmip.core.messages.payloads import destroy
from kmip.core.messages.payloads import register
from kmip.core.messages.payloads import locate

# TODO (peter-hamilton) Replace with PayloadFactories
REQUEST_MAP = {enums.Operation.CREATE: create.CreateRequestPayload,
               enums.Operation.GET: get.GetRequestPayload,
               enums.Operation.DESTROY: destroy.DestroyRequestPayload,
               enums.Operation.REGISTER: register.RegisterRequestPayload,
               enums.Operation.LOCATE: locate.LocateRequestPayload}

RESPONSE_MAP = {enums.Operation.CREATE: create.CreateResponsePayload,
                enums.Operation.GET: get.GetResponsePayload,
                enums.Operation.REGISTER: register.RegisterResponsePayload,
                enums.Operation.DESTROY: destroy.DestroyResponsePayload,
                enums.Operation.LOCATE: locate.LocateResponsePayload}
