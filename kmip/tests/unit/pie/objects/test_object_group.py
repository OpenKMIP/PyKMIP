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

import sqlalchemy
import testtools

from kmip.pie import objects
from kmip.pie import sqltypes

class TestObjectGroup(testtools.TestCase):
    """
    Test suite for ObjectGroup.
    """

    def setUp(self):
        super(TestObjectGroup, self).setUp()

    def tearDown(self):
        super(TestObjectGroup, self).tearDown()

    def test_init(self):
        """
        Test that an ObjectGroup object can be instantiated.
        """
        object_group = objects.ObjectGroup()

        self.assertIsNone(object_group.object_group)

    def test_invalid_object_group(self):
        """
        Test that a TypeError is raised when an invalid object group value
        is used to construct an ObjectGroup attribute.
        """
        kwargs = {"object_group": []}
        self.assertRaisesRegex(
            TypeError,
            "The object group must be a string.",
            objects.ObjectGroup,
            **kwargs
        )

        args = (
            objects.ObjectGroup(),
            "object_group",
            []
        )
        self.assertRaisesRegex(
            TypeError,
            "The object group must be a string.",
            setattr,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to an ObjectGroup attribute.
        """
        object_group = objects.ObjectGroup(object_group="Group1")

        expected = "ObjectGroup({})".format(
            "object_group='{}'".format("Group1")
        )
        observed = repr(object_group)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an ObjectGroup attribute.
        """
        object_group = objects.ObjectGroup(object_group="Group1")

        expected = str(
            {
                "object_group": "Group1"
            }
        )
        observed = str(object_group)

        self.assertEqual(expected, observed)

    def test_comparison_on_equal(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two ObjectGroup attributes with the same
        data.
        """
        a = objects.ObjectGroup()
        b = objects.ObjectGroup()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.ObjectGroup(object_group="Group1")
        b = objects.ObjectGroup(object_group="Group1")

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_object_groups(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ObjectGroup attributes with different object groups.
        """
        a = objects.ObjectGroup(object_group="a")
        b = objects.ObjectGroup(object_group="b")

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing an ObjectGroup attribute to a non ObjectGroup attribute.
        """
        a = objects.ObjectGroup()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_save(self):
        """
        Test that an ObjectGroup attribute can be saved using SQLAlchemy. This
        test will add an attribute instance to the database, verify that no
        exceptions are thrown, and check that its ID was set.
        """
        object_group = objects.ObjectGroup(object_group="Group1")

        engine = sqlalchemy.create_engine("sqlite:///:memory:", echo=True)
        sqltypes.Base.metadata.create_all(engine)

        session = sqlalchemy.orm.sessionmaker(bind=engine)()
        session.add(object_group)
        session.commit()

        self.assertIsNotNone(object_group.id)

    def test_get(self):
        """
        Test that an ObjectGroup attribute can be saved and then retrieved
        using SQLAlchemy. This test adds the attribute to the database and then
        retrieves it by ID and verifies its values.
        """
        object_group = objects.ObjectGroup(object_group="Group1")

        engine = sqlalchemy.create_engine("sqlite:///:memory:", echo=True)
        sqltypes.Base.metadata.create_all(engine)

        session = sqlalchemy.orm.sessionmaker(bind=engine)()
        session.add(object_group)
        session.commit()

        # Grab the ID now before making a new session to avoid a Detached error
        # See http://sqlalche.me/e/bhk3 for more info.
        object_group_id = object_group.id

        session = sqlalchemy.orm.sessionmaker(bind=engine)()
        retrieved_group = session.query(
            objects.ObjectGroup
        ).filter(
            objects.ObjectGroup.id == object_group_id
        ).one()
        session.commit()

        self.assertEqual("Group1", retrieved_group.object_group)
