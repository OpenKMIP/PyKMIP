# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

import abc
import six

from kmip.core import enums


@six.add_metaclass(abc.ABCMeta)
class ManagedObjectRepo(object):
    """Stores and manages KMIP managed objects.

    The KMIP specification details the managed objects that are stored by a
    KMIP server. This repository abstraction is an interface for KMIP servers
    to store managed objects.

    The managed objects referenced in this spec are all from the Pie API. Those
    classes are currently found in kmip.pie.objects.

    A ManagedObjectRepo not only manages the storage of managed objects, but it
    also must provide methods for transaction management. The methods allow a
    caller to begin, commit, and rollback transactions. This allows a caller to
    perform atomic transactions.

    NOTE: This interface is intended for single-threaded applications. In the
    future this interface is likely to be enhanced for multi-threaded
    applications. When callers of the interface call get_transaction this will
    create a class variable to store the current transaction. Then subsequent
    calls to save, get, commit, etc. will be assumed to be in the same
    transaction.

    The future likely change will be to add a return value to get_transaction
    that returns a reference to a transaction object. In addition each method
    will add a kwarg for transaction.
    """

    @abc.abstractmethod
    def begin_transaction(self):
        """Begins a transaction

        This begins a new transaction. If a transaction is already in process
        then this throws an error.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def commit(self):
        """Commits the transaction

        This commits the transaction and ends the current transaction. After
        this is called then begin_transaction may be called again to begin
        another transaction.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def rollback(self):
        """Rollback the current transaction

        The rolls back the current transaction and ends the current
        transaction. After this is called then begin_transaction may be called
        again to begin another transaction.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def save(self, managed_object):
        """Save a managed object

        This saves a managed object into the repository and returns a UID
        string that can be used to reference the object in the repository.
        :param managed_object: managed object to save
        :returns: a UID string that can be used to retrieve the object later
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, uid):
        """Retrieve a managed object

        Retrieve a managed object from the repository. The UID is used to
        identify the managed object to return. The UID is returned from the
        save call.

        :param uuid: UUID of the managed object
        :returns: managed_object if object exists, otherwise None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def search(self, attributes, max_items,
               storage_status_mask=(enums.StorageStatusMask.ONLINE_STORAGE),
               object_group_member=None):
        """Search for a managed object.

        Search for and return managed objects that have all of the attributes.
        If no managed objects possess all of the properties then None is
        returned.

        The attributes parameter is a dictionary of attributes. The key for
        each attribute is one of those defined in kmip.pie.api.KmipClient. The
        value is dependent upon the type. The list below gives the value types
        for each of the KMIP types.

        KMIP type - Python type
        Structure - class type from Pie API
        Integer (except bitmasks) - int
        Long integer - int or long
        Big integer - TBD as the Pie API has yet to address this data type
        Enumeration - Enum (see kmip.core.enums)
        Boolean - boolean
        Text string - str (alphanumeric and white space characters, no regex)
        Byte string - str (Python 2.x) or bytes (Python 3.x)
        Date-Time - datetime object or tuple of two datetime objects
        Interval - int

        For KMIP objects that represent integer bitmasks the expected value
        will be a tuple that consists of Enums for the valid bitmask bits. An
        example is the cryptographic usage mask bitmask. If a caller wanted to
        search for all keys that are used for decryption and signing then the
        tuple would contain the values
        (enums.CryptographicUsageMask.DECRYPT,enums.CryptographicUsageMask.SIGN).
        The matching candidates shall have each of those bits set in their bit
        mask, and may have additional bits in the mask set. See the KMIP
        specification for more details.

        For KMIP date-time types the value can be a single datetime object or a
        tuple of two datetime objects. If the value is a single datetime object
        then all matching candidates will have that date attribute greater than
        or equal to the datetime value in the search attribute. If the value is
        a tuple then the tuple will be composed of two datetime objects in the
        format (start_time, end_time) and objects whose datetime attribute is
        in the range start_time <= datetime <= end_time will be considered
        matching candidates.

        For KMIP attributes that are structures then each of the properties of
        that structure are used in the search except for those that are None.
        The structures will be represented by one of the classes from the Pie
        API.

        :param attributes: dictionary of attributes to be matched
        :param max_items: maximum number of objects to return
        :param storage_status_mask: tuple of enums.StorageStatusMask values
        :param object_group_member: An Enum of type enums.ObjectGroupMember
        that indicates the object group member type or None to ignore this
        criterion
        :returns: managed_objects if objects found, otherwise None
        """
        raise NotImplementedError

    @abc.abstractmethod
    def update(self, managed_object):
        """Updates a managed object

        Updates the values for a managed_object. This call may or may not be
        necessary for certain backends. This call ensures that the managed
        object is updated. In some backends the code to persist the update may
        happen automatically. This would be the case for a memory backend.

        Other backends may require this call. For those backends this will
        detect the changes between the object from when it was associated with
        this transaction and this call. It will then persist those changes.
        This could happen with a database backend to issue UPDATE commands.

        All libraries that call this interface should call this method when
        updating objects. This will ensure the proper behavior.
        :param managed_object: managed object in the current transaction
        :returns: True if object existed and successfully updated, otherwise
        False
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, uid):
        """Delete a managed object from the repository

        Delete a managed object from the repository.
        :param uid: UID of the managed object
        :returns: True if successfully deleted, False if not found
        """
        raise NotImplementedError
