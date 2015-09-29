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


class ManagedObjectRepo(object):
    """Stores and manages KMIP managed objects.

    The KMIP specification details the managed objects that are stored by a
    KMIP server. This repository abstraction is an interface for KMIP servers
    to store managed objects.
    """

    def __init__(self):
        pass

    def save(self, managed_object, attributes):
        """Save a managed object

        This saves a managed object into the repository and returns a UUID
        string that can be used to reference the object in the repository.
        :param managed_object: managed object to save from secrets.py
        :param attributes: attributes to store with the managed object
        :returns: a UUID string that can be used to retrieve the object later
        """
        raise NotImplementedError

    def get(self, uuid):
        """Retrieve a managed object

        Retrieve a managed object from the repository. The UUID is used to
        identify the managed object to return. The UUID is returned from the
        save call.

        A tuple is returned that contains the managed object and all of its
        attributes.
        :param uuid: UUID of the managed object
        :returns: (managed_object, attributes) if object exists, otherwise
        (None, None)
        """
        raise NotImplementedError

    def update(self, uuid, managed_object, attributes):
        """Updates a managed object

        Updates the values for a managed_object.
        :param uuid: UUID of the managed object
        :param managed_object: managed object
        :param attributes: attributes to store with the managed object
        :returns: True if object existed and successfully updated, otherwise
        False
        """
        raise NotImplementedError

    def delete(self, uuid):
        """Delete a managed object from the repository

        Delete a managed object from the repository.
        :param uuid: UUID of the managed object
        :returns: True if successfully deleted, False if not found
        """
        raise NotImplementedError
