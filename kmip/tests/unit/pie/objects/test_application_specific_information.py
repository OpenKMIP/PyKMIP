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

class TestApplicationSpecificInformation(testtools.TestCase):
    """
    Test suite for ApplicationSpecificInformation.
    """

    def setUp(self):
        super(TestApplicationSpecificInformation, self).setUp()

    def tearDown(self):
        super(TestApplicationSpecificInformation, self).tearDown()

    def test_init(self):
        """
        Test that an ApplicationSpecificInformation object can be instantiated.
        """
        app_specific_info = objects.ApplicationSpecificInformation()

        self.assertIsNone(app_specific_info.application_namespace)
        self.assertIsNone(app_specific_info.application_data)

    def test_invalid_application_namespace(self):
        """
        Test that a TypeError is raised when an invalid application namespace
        value is used to construct an ApplicationSpecificInformation attribute.
        """
        kwargs = {"application_namespace": []}
        self.assertRaisesRegex(
            TypeError,
            "The application namespace must be a string.",
            objects.ApplicationSpecificInformation,
            **kwargs
        )

        args = (
            objects.ApplicationSpecificInformation(),
            "application_namespace",
            []
        )
        self.assertRaisesRegex(
            TypeError,
            "The application namespace must be a string.",
            setattr,
            *args
        )

    def test_invalid_application_data(self):
        """
        Test that a TypeError is raised when an invalid application data value
        is used to construct an ApplicationSpecificInformation attribute.
        """
        kwargs = {"application_data": []}
        self.assertRaisesRegex(
            TypeError,
            "The application data must be a string.",
            objects.ApplicationSpecificInformation,
            **kwargs
        )

        args = (
            objects.ApplicationSpecificInformation(),
            "application_data",
            []
        )
        self.assertRaisesRegex(
            TypeError,
            "The application data must be a string.",
            setattr,
            *args
        )

    def test_repr(self):
        """
        Test that repr can be applied to an ApplicationSpecificInformation
        attribute.
        """
        app_specific_info = objects.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        args = [
            "application_namespace='{}'".format("ssl"),
            "application_data='{}'".format("www.example.com")
        ]

        expected = "ApplicationSpecificInformation({})".format(", ".join(args))
        observed = repr(app_specific_info)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to an ApplicationSpecificInformation
        attribute.
        """
        app_specific_info = objects.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        expected = str(
            {
                "application_namespace": "ssl",
                "application_data": "www.example.com"
            }
        )
        observed = str(app_specific_info)

        self.assertEqual(expected, observed)

    def test_comparison_on_equal(self):
        """
        Test that the equality/inequality operators return True/False when
        comparing two ApplicationSpecificInformation attributes with the same
        data.
        """
        a = objects.ApplicationSpecificInformation()
        b = objects.ApplicationSpecificInformation()

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = objects.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )
        b = objects.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)
        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_comparison_on_different_application_namespaces(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ApplicationSpecificInformation attributes with different
        application namespaces.
        """
        a = objects.ApplicationSpecificInformation(
            application_namespace="a"
        )
        b = objects.ApplicationSpecificInformation(
            application_namespace="b"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_different_application_data(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing two ApplicationSpecificInformation attributes with different
        application data.
        """
        a = objects.ApplicationSpecificInformation(
            application_data="a"
        )
        b = objects.ApplicationSpecificInformation(
            application_data="b"
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_comparison_on_type_mismatch(self):
        """
        Test that the equality/inequality operators return False/True when
        comparing an ApplicationSpecificInformation attribute to a non
        ApplicationSpecificInformation attribute.
        """
        a = objects.ApplicationSpecificInformation()
        b = "invalid"

        self.assertFalse(a == b)
        self.assertFalse(b == a)
        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_save(self):
        """
        Test that an ApplicationSpecificInformation attribute can be saved
        using SQLAlchemy. This test will add an attribute instance to the
        database, verify that no exceptions are thrown, and check that its
        ID was set.
        """
        app_specific_info = objects.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        engine = sqlalchemy.create_engine("sqlite:///:memory:", echo=True)
        sqltypes.Base.metadata.create_all(engine)

        session = sqlalchemy.orm.sessionmaker(bind=engine)()
        session.add(app_specific_info)
        session.commit()

        self.assertIsNotNone(app_specific_info.id)

    def test_get(self):
        """
        Test that an ApplicationSpecificInformation attribute can be saved
        and then retrieved using SQLAlchemy. This test adds the attribute to
        the database and then retrieves it by ID and verifies its values.
        """
        app_specific_info = objects.ApplicationSpecificInformation(
            application_namespace="ssl",
            application_data="www.example.com"
        )

        engine = sqlalchemy.create_engine("sqlite:///:memory:", echo=True)
        sqltypes.Base.metadata.create_all(engine)

        session = sqlalchemy.orm.sessionmaker(bind=engine)()
        session.add(app_specific_info)
        session.commit()

        # Grab the ID now before making a new session to avoid a Detached error
        # See http://sqlalche.me/e/bhk3 for more info.
        app_specific_info_id = app_specific_info.id

        session = sqlalchemy.orm.sessionmaker(bind=engine)()
        retrieved_info = session.query(
            objects.ApplicationSpecificInformation
        ).filter(
            objects.ApplicationSpecificInformation.id == app_specific_info_id
        ).one()
        session.commit()

        self.assertEqual("ssl", retrieved_info.application_namespace)
        self.assertEqual("www.example.com", retrieved_info.application_data)
