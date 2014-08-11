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

from kmip.core.repo.repo import ManagedObjectRepo


class MemRepo(ManagedObjectRepo):

    def __init__(self):
        self.repo = {}
        self.uuid = 1

    def save(self, managed_object, attributes):
        # TODO (nate) verify the parameters
        uuid = "{0}".format(self.uuid)
        self.repo[uuid] = (managed_object, attributes)
        self.uuid += 1
        return uuid

    def get(self, uuid):
        if uuid is None or uuid not in self.repo:
            return (None, None)
        return self.repo[uuid]

    def update(self, uuid, managed_object, attributes):
        if uuid is None:
            return False
        self.repo[uuid] = (managed_object, attributes)
        return True

    def delete(self, uuid):
        if uuid is None or uuid not in self.repo:
            return False
        del self.repo[uuid]
        return True
