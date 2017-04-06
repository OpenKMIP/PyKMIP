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

import testtools

from kmip.pie import api


class DummyKmipClient(api.KmipClient):
    """
    A dummy KmipClient subclass for testing purposes.
    """

    def __init__(self):
        super(DummyKmipClient, self).__init__()

    def create(self, algorithm, length):
        super(DummyKmipClient, self).create(algorithm, length)

    def create_key_pair(self, algorithm, length):
        super(DummyKmipClient, self).create_key_pair(algorithm, length)

    def register(self, managed_object, *args, **kwargs):
        super(DummyKmipClient, self).register(managed_object)

    def get(self, uid, *args, **kwargs):
        super(DummyKmipClient, self).get(uid)

    def get_attribute_list(self, uid, *args, **kwargs):
        super(DummyKmipClient, self).get_attribute_list(uid)

    def destroy(self, uid):
        super(DummyKmipClient, self).destroy(uid)

    def mac(self, uid, algorithm, data):
        super(DummyKmipClient, self).mac(uid, algorithm, data)


class TestKmipClient(testtools.TestCase):
    """
    Test suite for KmipClient.

    Since KmipClient is an ABC abstract class, all tests are run against a
    dummy subclass defined above, DummyKmipClient.
    """

    def setUp(self):
        super(TestKmipClient, self).setUp()

    def tearDown(self):
        super(TestKmipClient, self).tearDown()

    def test_init(self):
        """
        Test that a complete subclass of KmipClient can be instantiated.
        """
        DummyKmipClient()

    def test_create(self):
        """
        Test that the create method can be called without error.
        """
        dummy = DummyKmipClient()
        dummy.create('algoritm', 'length')

    def test_create_key_pair(self):
        """
        Test that the create_key_pair method can be called without error.
        """
        dummy = DummyKmipClient()
        dummy.create_key_pair('algoritm', 'length')

    def test_register(self):
        """
        Test that the register method can be called without error.
        """
        dummy = DummyKmipClient()
        dummy.register('secret')

    def test_get(self):
        """
        Test that the get method can be called without error.
        """
        dummy = DummyKmipClient()
        dummy.get('uid')

    def test_get_attribute_list(self):
        """
        Test that the get_attribute_list method can be called without error.
        """
        dummy = DummyKmipClient()
        dummy.get_attribute_list('uid')

    def test_destroy(self):
        """
        Test that the destroy method can be called without error.
        """
        dummy = DummyKmipClient()
        dummy.destroy('uid')

    def test_mac(self):
        """
        Test that the mac method can be called without error.
        """
        dummy = DummyKmipClient()
        dummy.mac('data', 'uid', 'algorithm')
