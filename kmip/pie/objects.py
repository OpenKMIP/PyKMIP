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

from abc import ABCMeta
from abc import abstractmethod

from six import add_metaclass


@add_metaclass(ABCMeta)
class ManagedObject:
    """
    The abstract base object of the simplified KMIP object hierarchy.

    A ManagedObject is a core KMIP object that is the subject of key
    management operations. It contains various attributes that are common to
    all types of ManagedObjects, including keys, certificates, and various
    types of secret or sensitive data.

    For more information, see Section 2.2 of the KMIP 1.1 specification.

    Attributes:
        value: The value of the ManagedObject. Type varies, usually bytes.
        unique_identifier: The string ID of the ManagedObject.
        names: A list of names associated with the ManagedObject.
        object_type: An enumeration associated with the type of ManagedObject.
    """

    @abstractmethod
    def __init__(self):
        """
        Create a ManagedObject.
        """
        self.value = None

        self.unique_identifier = None
        self.names = list()
        self._object_type = None

        # All remaining attributes are not considered part of the public API
        # and are subject to change.
        self._application_specific_informations = list()
        self._contact_information = None
        self._object_groups = list()
        self._operation_policy_name = None

        # The following attributes are placeholders for attributes that are
        # unsupported by kmip.core
        self._archive_date = None
        self._initial_date = None
        self._last_change_date = None

    @property
    def object_type(self):
        """
        Accessor and property definition for the object type attribute.

        Returns:
            ObjectType: An ObjectType enumeration that corresponds to the
                class of the object.
        """
        return self._object_type

    @object_type.setter
    def object_type(self, value):
        """
        Set blocker for the object type attribute.

        Raises:
            AttributeError: Always raised to block setting of attribute.
        """
        raise AttributeError("object type cannot be set")

    @abstractmethod
    def __repr__(self):
        pass

    @abstractmethod
    def __str__(self):
        pass

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __ne__(self, other):
        pass
