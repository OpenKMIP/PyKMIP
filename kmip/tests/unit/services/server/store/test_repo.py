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

from testtools import TestCase

from kmip.core import enums
from kmip.services.server.store.repo import ManagedObjectRepo


class DummyManagedObjectRepo(ManagedObjectRepo):
    """
    A dummy ManagedObjectRepo subclass for testing purposes. It's main purpose
    is to get code coverage to 100% for ManagedObjectRepo interface, so code
    coverage gate will succeed.
    """

    def begin_transaction(self):
        super(DummyManagedObjectRepo, self).begin_transaction()

    def commit(self):
        super(DummyManagedObjectRepo, self).commit()

    def rollback(self):
        super(DummyManagedObjectRepo, self).rollback()

    def save(self, managed_object):
        super(DummyManagedObjectRepo, self).save(managed_object)

    def get(self, uid):
        super(DummyManagedObjectRepo, self).get(uid)

    def search(self, attributes, max_items,
               storage_status_mask=(enums.StorageStatusMask.ONLINE_STORAGE),
               object_group_member=None):
        super(DummyManagedObjectRepo, self).search(
            attributes, max_items, storage_status_mask, object_group_member)

    def update(self, managed_object):
        super(DummyManagedObjectRepo, self).update(managed_object)

    def delete(self, uid):
        super(DummyManagedObjectRepo, self).delete(uid)


class TestManagedObject(TestCase):
    """
    Test suite for ManagedObject.

    Since ManagedObject is an ABC abstract class, all tests are run against a
    dummy subclass defined above, DummyManagedObject.
    """

    def setUp(self):
        super(TestManagedObject, self).setUp()

    def tearDown(self):
        super(TestManagedObject, self).tearDown()

    def test_managed_object_repo_is_abstract(self):
        """
        Asserts that ManagedObjectRepo is abstract and cannot be initialized.
        """
        self.assertRaises(TypeError, ManagedObjectRepo)

    def test_dummy_repo(self):
        """
        Invokes all of the methods of the dummy repo to get code coverage to
        100%.
        """
        repo = DummyManagedObjectRepo()
        self.assertRaises(NotImplementedError, repo.begin_transaction)
        self.assertRaises(NotImplementedError, repo.save, None)
        self.assertRaises(NotImplementedError, repo.get, None)
        self.assertRaises(NotImplementedError, repo.search, None, None)
        self.assertRaises(NotImplementedError, repo.update, None)
        self.assertRaises(NotImplementedError, repo.delete, None)
        self.assertRaises(NotImplementedError, repo.commit)
        self.assertRaises(NotImplementedError, repo.rollback)
