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

from enum import Enum

from kmip.core.factories.attribute_values import AttributeValueFactory

from kmip.core.objects import Attribute

from kmip.core import utils

class AttributeFactory(object):

    def __init__(self):
        self.value_factory = AttributeValueFactory()

    def _create_attribute(self, name, value, index):
        attribute_name = Attribute.AttributeName(name)

        if index is None:
            return Attribute(attribute_name=attribute_name,
                             attribute_value=value)
        else:
            attribute_index = Attribute.AttributeIndex(index)
            return Attribute(attribute_name=attribute_name,
                             attribute_index=attribute_index,
                             attribute_value=value)

    def create_attribute(self, name, value, index=None):
        value = self.value_factory.create_attribute_value(name, value)

        if isinstance(name, Enum):
            name = name.value
        elif isinstance(name, str):
            # Name is already a string, pass
            pass
        else:
            msg = utils.build_er_error(Attribute, 'name',
                                       '{0} or {1}'.format('Enum', 'str'),
                                       type(name))
            raise TypeError(msg)

        return self._create_attribute(name, value, index)
