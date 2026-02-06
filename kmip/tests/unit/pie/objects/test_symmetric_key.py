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

import binascii
import testtools

from kmip.core import enums
from kmip.pie import sqltypes
from kmip.pie.objects import ManagedObject, SymmetricKey
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

class TestSymmetricKey(testtools.TestCase):
    """
    Test suite for SymmetricKey.
    """

    def setUp(self):
        super(TestSymmetricKey, self).setUp()

        # Key values taken from Sections 14.2, 15.2, and 18.1 of the KMIP 1.1
        # testing documentation.
        self.bytes_128a = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
            b'\x0F')
        self.bytes_128b = (
            b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE'
            b'\xFF')
        self.bytes_256a = (
            b'\x00\x00\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77'
            b'\x88\x88\x99\x99\xAA\xAA\xBB\xBB\xCC\xCC\xDD\xDD\xEE\xEE\xFF'
            b'\xFF')
        self.bytes_256b = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E'
            b'\x1F')
        self.engine = create_engine('sqlite:///:memory:', echo=True)
        sqltypes.Base.metadata.create_all(self.engine)

    def tearDown(self):
        super(TestSymmetricKey, self).tearDown()

    def test_init(self):
        """
        Test that a SymmetricKey object can be instantiated.
        """
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)

        self.assertEqual(key.cryptographic_algorithm,
                         enums.CryptographicAlgorithm.AES)
        self.assertEqual(key.cryptographic_length, 128)
        self.assertEqual(key.value, self.bytes_128a)
        self.assertEqual(key.cryptographic_usage_masks, list())
        self.assertEqual(key.names, ['Symmetric Key'])

    def test_init_with_args(self):
        """
        Test that a SymmetricKey object can be instantiated with all arguments.
        """
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128a,
            masks=[enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT],
            name='Test Symmetric Key')

        self.assertEqual(key.cryptographic_algorithm,
                         enums.CryptographicAlgorithm.AES)
        self.assertEqual(key.cryptographic_length, 128)
        self.assertEqual(key.value, self.bytes_128a)
        self.assertEqual(key.cryptographic_usage_masks,
                         [enums.CryptographicUsageMask.ENCRYPT,
                          enums.CryptographicUsageMask.DECRYPT])
        self.assertEqual(key.names, ['Test Symmetric Key'])

    def test_get_object_type(self):
        """
        Test that the object type can be retrieved from the SymmetricKey.
        """
        expected = enums.ObjectType.SYMMETRIC_KEY
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        observed = key.object_type

        self.assertEqual(expected, observed)

    def test_validate_on_invalid_algorithm(self):
        """
        Test that a TypeError is raised when an invalid algorithm value is
        used to construct a SymmetricKey.
        """
        args = ('invalid', 128, self.bytes_128a)

        self.assertRaises(TypeError, SymmetricKey, *args)

    def test_validate_on_invalid_length(self):
        """
        Test that a TypeError is raised when an invalid length value is used
        to construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 'invalid', self.bytes_128a)

        self.assertRaises(TypeError, SymmetricKey, *args)

    def test_validate_on_invalid_value(self):
        """
        Test that a TypeError is raised when an invalid value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, 0)

        self.assertRaises(TypeError, SymmetricKey, *args)

    def test_validate_on_invalid_masks(self):
        """
        Test that a TypeError is raised when an invalid masks value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        kwargs = {'masks': 'invalid'}

        self.assertRaises(TypeError, SymmetricKey, *args, **kwargs)

    def test_validate_on_invalid_mask(self):
        """
        Test that a TypeError is raised when an invalid mask value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        kwargs = {'masks': ['invalid']}

        self.assertRaises(TypeError, SymmetricKey, *args, **kwargs)

    def test_validate_on_invalid_name(self):
        """
        Test that a TypeError is raised when an invalid name value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        kwargs = {'name': 0}

        self.assertRaises(TypeError, SymmetricKey, *args, **kwargs)

    def test_validate_on_invalid_length_value(self):
        """
        Test that a ValueError is raised when an invalid length value is
        used to construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 256, self.bytes_128a)

        self.assertRaises(ValueError, SymmetricKey, *args)

    def test_validate_on_invalid_value_length(self):
        """
        Test that a ValueError is raised when an invalid value is used to
        construct a SymmetricKey.
        """
        args = (enums.CryptographicAlgorithm.AES, 128, self.bytes_256a)

        self.assertRaises(ValueError, SymmetricKey, *args)

    def test_repr(self):
        """
        Test that repr can be applied to a SymmetricKey.
        """
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128a
        )

        args = "{0}, {1}, {2}, {3}".format(
            "algorithm={0}".format(enums.CryptographicAlgorithm.AES),
            "length={0}".format(128),
            "value={0}".format(binascii.hexlify(self.bytes_128a)),
            "key_wrapping_data={0}".format({})
        )
        expected = "SymmetricKey({0})".format(args)
        observed = repr(key)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a SymmetricKey.
        """
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        expected = str(binascii.hexlify(self.bytes_128a))
        observed = str(key)

        self.assertEqual(expected, observed)

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two
        SymmetricKey objects with the same data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_algorithm(self):
        """
        Test that the equality operator returns False when comparing two
        SymmetricKey objects with different data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.RSA, 128, self.bytes_128a)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_length(self):
        """
        Test that the equality operator returns False when comparing two
        SymmetricKey objects with different data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 256, self.bytes_256a)
        b.value = self.bytes_128a

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_value(self):
        """
        Test that the equality operator returns False when comparing two
        SymmetricKey objects with different data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128b)

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_key_wrapping_data(self):
        """
        Test that the equality operator returns False when comparing two
        SymmetricKey objects with different key wrapping data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128a,
            key_wrapping_data={}
        )
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128a,
            key_wrapping_data={
                'wrapping_method': enums.WrappingMethod.ENCRYPT
            }
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing a
        SymmetricKey object to a non-SymmetricKey object.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing
        two SymmetricKey objects with the same internal data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_algorithm(self):
        """
        Test that the inequality operator returns True when comparing two
        SymmetricKey objects with different data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.RSA, 128, self.bytes_128a)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_length(self):
        """
        Test that the inequality operator returns True when comparing two
        SymmetricKey objects with different data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 256, self.bytes_256a)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_value(self):
        """
        Test that the inequality operator returns True when comparing two
        SymmetricKey objects with different data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128b)

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_key_wrapping_data(self):
        """
        Test that the inequality operator returns True when comparing two
        SymmetricKey objects with different key wrapping data.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128a,
            key_wrapping_data={}
        )
        b = SymmetricKey(
            enums.CryptographicAlgorithm.AES,
            128,
            self.bytes_128a,
            key_wrapping_data={
                'wrapping_method': enums.WrappingMethod.ENCRYPT
            }
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns True when comparing a
        SymmetricKey object to a non-SymmetricKey object.
        """
        a = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        b = "invalid"

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_save(self):
        """
        Test that the object can be saved using SQLAlchemy. This will add it to
        the database, verify that no exceptions are thrown, and check that its
        unique identifier was set.
        """
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a)
        Session = sessionmaker(bind=self.engine)
        session = Session()
        session.add(key)
        session.commit()
        self.assertIsNotNone(key.unique_identifier)

    def test_get(self):
        """
        Test that the object can be saved and then retrieved using SQLAlchemy.
        This adds is to the database and then retrieves it by ID and verifies
        some of the attributes.
        """
        test_name = 'bowser'
        masks = [enums.CryptographicUsageMask.ENCRYPT,
                 enums.CryptographicUsageMask.DECRYPT]
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a,
            masks=masks,
            name=test_name)
        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(1, len(get_obj.names))
        self.assertEqual([test_name], get_obj.names)
        self.assertEqual(enums.ObjectType.SYMMETRIC_KEY, get_obj.object_type)
        self.assertEqual(self.bytes_128a, get_obj.value)
        self.assertEqual(enums.CryptographicAlgorithm.AES,
                         get_obj.cryptographic_algorithm)
        self.assertEqual(128, get_obj.cryptographic_length)
        self.assertEqual(enums.KeyFormatType.RAW, get_obj.key_format_type)
        self.assertEqual(masks, get_obj.cryptographic_usage_masks)

    def test_add_multiple_names(self):
        """
        Test that multiple names can be added to a managed object. This
        verifies a few properties. First this verifies that names can be added
        using simple strings. It also verifies that the index for each
        subsequent string is set accordingly. Finally this tests that the names
        can be saved and retrieved from the database.
        """
        expected_names = ['bowser', 'frumpy', 'big fat cat']
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a,
            name=expected_names[0])
        key.names.append(expected_names[1])
        key.names.append(expected_names[2])
        self.assertEqual(3, key.name_index)
        expected_mo_names = list()
        for i, name in enumerate(expected_names):
            expected_mo_names.append(sqltypes.ManagedObjectName(name, i))
        self.assertEqual(expected_mo_names, key._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_remove_name(self):
        """
        Tests that a name can be removed from the list of names. This will
        verify that the list of names is correct. It will verify that updating
        this object removes the name from the database.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        remove_index = 1
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a,
            name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])
        key.names.pop(remove_index)
        self.assertEqual(3, key.name_index)

        expected_names = list()
        expected_mo_names = list()
        for i, name in enumerate(names):
            if i != remove_index:
                expected_names.append(name)
                expected_mo_names.append(sqltypes.ManagedObjectName(name, i))
        self.assertEqual(expected_names, key.names)
        self.assertEqual(expected_mo_names, key._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_remove_and_add_name(self):
        """
        Tests that names can be removed from the list of names and more added.
        This will verify that the list of names is correct. It will verify that
        updating this object removes the name from the database. It will verify
        that the indices for the removed names are not reused.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a,
            name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])
        key.names.pop()
        key.names.pop()
        key.names.append('dog')
        self.assertEqual(4, key.name_index)

        expected_names = ['bowser', 'dog']
        expected_mo_names = list()
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[0],
                                                            0))
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[1],
                                                            3))
        self.assertEqual(expected_names, key.names)
        self.assertEqual(expected_mo_names, key._names)

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        get_obj = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_add_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will add a
        name to it in one session, and then retrieve it in another session to
        verify that it has all of the correct names.

        This test and the subsequent test_udpate_* methods are different than
        the name tests above because these are updating objects already stored
        in the database. This tests will simulate what happens when the KMIP
        client calls an add attribute method.
        """
        first_name = 'bowser'
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a,
            name=first_name)
        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        added_name = 'frumpy'
        expected_names = [first_name, added_name]
        expected_mo_names = list()
        for i, name in enumerate(expected_names):
            expected_mo_names.append(sqltypes.ManagedObjectName(name, i))

        session = Session()
        update_key = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        update_key.names.append(added_name)
        session.commit()

        session = Session()
        get_obj = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_remove_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will
        remove a name from it in one session, and then retrieve it in another
        session to verify that it has all of the correct names.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        remove_index = 1
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a,
            name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        expected_names = list()
        expected_mo_names = list()
        for i, name in enumerate(names):
            if i != remove_index:
                expected_names.append(name)
                expected_mo_names.append(sqltypes.ManagedObjectName(name, i))

        session = Session()
        update_key = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        update_key.names.pop(remove_index)
        session.commit()

        session = Session()
        get_obj = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)

    def test_update_with_remove_and_add_name(self):
        """
        Tests that an OpaqueObject already stored in the database can be
        updated. This will store an OpaqueObject in the database. It will
        remove a name and add another one to it in one session, and then
        retrieve it in another session to verify that it has all of the correct
        names. This simulates multiple operation being sent for the same
        object.
        """
        names = ['bowser', 'frumpy', 'big fat cat']
        key = SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.bytes_128a,
            name=names[0])
        key.names.append(names[1])
        key.names.append(names[2])

        Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        session = Session()
        session.add(key)
        session.commit()

        session = Session()
        update_key = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        update_key.names.pop()
        update_key.names.pop()
        update_key.names.append('dog')
        session.commit()

        expected_names = ['bowser', 'dog']
        expected_mo_names = list()
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[0],
                                                            0))
        expected_mo_names.append(sqltypes.ManagedObjectName(expected_names[1],
                                                            3))

        session = Session()
        get_obj = session.query(SymmetricKey).filter(
            ManagedObject.unique_identifier == key.unique_identifier
            ).one()
        session.commit()
        self.assertEqual(expected_names, get_obj.names)
        self.assertEqual(expected_mo_names, get_obj._names)
