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

from kmip.core import enums
from kmip.core import objects
from kmip.core import primitives
from kmip.core import utils

from kmip.core.messages import payloads

class TestRekeyRequestPayload(testtools.TestCase):
    """
    Test suite for the Rekey request payload.
    """

    def setUp(self):
        super(TestRekeyRequestPayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document,
        # Sections 9.2 and 9.4.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 1346d253-69d6-474c-8cd5-ad475a3e0a81
        #     Offset - 0
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Activation Date
        #             Attribute Value - Sun Jan 01 12:00:00 CET 2006
        #         Attribute
        #             Attribute Name - Process Start Date
        #             Attribute Value - Sun Jan 01 12:00:00 CET 2006
        #         Attribute
        #             Attribute Name - Protect Stop Date
        #             Attribute Value - Wed Jan 01 12:00:00 CET 2020
        #         Attribute
        #             Attribute Name - Deactivation Date
        #             Attribute Value - Wed Jan 01 12:00:00 CET 2020

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x01\x20'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x31\x33\x34\x36\x64\x32\x35\x33\x2D\x36\x39\x64\x36\x2D\x34\x37'
            b'\x34\x63\x2D\x38\x63\x64\x35\x2D\x61\x64\x34\x37\x35\x61\x33\x65'
            b'\x30\x61\x38\x31\x00\x00\x00\x00'
            b'\x42\x00\x58\x0A\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\xD8'
            b'\x42\x00\x08\x01\x00\x00\x00\x28'
            b'\x42\x00\x0A\x07\x00\x00\x00\x0F'
            b'\x41\x63\x74\x69\x76\x61\x74\x69\x6F\x6E\x20\x44\x61\x74\x65\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x43\xB7\xB6\x30'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x12'
            b'\x50\x72\x6F\x63\x65\x73\x73\x20\x53\x74\x61\x72\x74\x20\x44\x61'
            b'\x74\x65\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x43\xB7\xB6\x30'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x50\x72\x6F\x74\x65\x63\x74\x20\x53\x74\x6F\x70\x20\x44\x61\x74'
            b'\x65\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x5E\x0C\x7B\xB0'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x11'
            b'\x44\x65\x61\x63\x74\x69\x76\x61\x74\x69\x6F\x6E\x20\x44\x61\x74'
            b'\x65\x00\x00\x00\x00\x00\x00\x00'
            b'\x42\x00\x0B\x09\x00\x00\x00\x08\x00\x00\x00\x00\x5E\x0C\x7B\xB0'
        )

        # Encoding obtained from the KMIP 1.1 testing document, Section 9.1.
        #
        # This encoding matches the following set of values:
        # Request Payload
        #     Unique Identifier - 964d3dd2-5f06-4529-8bb8-ae630b6ca2e0

        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x39\x36\x34\x64\x33\x64\x64\x32\x2D\x35\x66\x30\x36\x2D\x34\x35'
            b'\x32\x39\x2D\x38\x62\x62\x38\x2D\x61\x65\x36\x33\x30\x62\x36\x63'
            b'\x61\x32\x65\x30\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x79\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestRekeyRequestPayload, self).tearDown()

    def test_init(self):
        """
        Test that a Rekey request payload can be constructed with no arguments.
        """
        payload = payloads.RekeyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a Rekey request payload can be constructed with valid values.
        """
        payload = payloads.RekeyRequestPayload(
            unique_identifier='00000000-2222-4444-6666-888888888888',
            offset=0,
            template_attribute=objects.TemplateAttribute()
        )

        self.assertEqual(
            '00000000-2222-4444-6666-888888888888',
            payload.unique_identifier
        )
        self.assertEqual(0, payload.offset)
        self.assertEqual(
            objects.TemplateAttribute(),
            payload.template_attribute
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Rekey request payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.RekeyRequestPayload,
            **kwargs
        )

        args = (payloads.RekeyRequestPayload(), 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_offset(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the offset of a Rekey request payload.
        """
        kwargs = {'offset': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Offset must be an integer.",
            payloads.RekeyRequestPayload,
            **kwargs
        )

        args = (payloads.RekeyRequestPayload(), 'offset', 'invalid')
        self.assertRaisesRegex(
            TypeError,
            "Offset must be an integer.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a Rekey request payload.
        """
        kwargs = {'template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute struct.",
            payloads.RekeyRequestPayload,
            **kwargs
        )

        args = (
            payloads.RekeyRequestPayload(),
            'template_attribute',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute struct.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Rekey request payload can be read from a data stream.
        """
        payload = payloads.RekeyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            '1346d253-69d6-474c-8cd5-ad475a3e0a81',
            payload.unique_identifier
        )
        self.assertEqual(0, payload.offset)
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Process Start Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.PROCESS_START_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Protect Stop Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.PROTECT_STOP_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Deactivation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.DEACTIVATION_DATE
                        )
                    )
                ]
            ),
            payload.template_attribute
        )

    def test_read_partial(self):
        """
        Test that a Rekey request payload can be read from a partial data
        stream.
        """
        payload = payloads.RekeyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.partial_encoding)

        self.assertEqual(
            '964d3dd2-5f06-4529-8bb8-ae630b6ca2e0',
            payload.unique_identifier
        )
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

    def test_read_empty(self):
        """
        Test that a Rekey request payload can be read from an empty data
        stream.
        """
        payload = payloads.RekeyRequestPayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.empty_encoding)

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.offset)
        self.assertEqual(None, payload.template_attribute)

    def test_write(self):
        """
        Test that a Rekey request payload can be written to a data stream.
        """
        payload = payloads.RekeyRequestPayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Process Start Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.PROCESS_START_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Protect Stop Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.PROTECT_STOP_DATE
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Deactivation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.DEACTIVATION_DATE
                        )
                    )
                ]
            )
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partial Rekey request payload can be written to a data
        stream.
        """
        payload = payloads.RekeyRequestPayload(
            unique_identifier='964d3dd2-5f06-4529-8bb8-ae630b6ca2e0'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_empty(self):
        """
        Test that an empty Rekey request payload can be written to a data
        stream.
        """
        payload = payloads.RekeyRequestPayload()
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.empty_encoding), len(stream))
        self.assertEqual(str(self.empty_encoding), str(stream))

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Rekey
        request payloads with the same data.
        """
        a = payloads.RekeyRequestPayload()
        b = payloads.RekeyRequestPayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.RekeyRequestPayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyRequestPayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two Rekey
        request payloads with different unique identifiers.
        """
        a = payloads.RekeyRequestPayload(
            unique_identifier='a'
        )
        b = payloads.RekeyRequestPayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_offset(self):
        """
        Test that the equality operator returns False when comparing two Rekey
        request payloads with different offsets.
        """
        a = payloads.RekeyRequestPayload(
            offset=0
        )
        b = payloads.RekeyRequestPayload(
            offset=1
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two Rekey
        request payloads with different template attributes.
        """
        a = payloads.RekeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Protect Stop Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.PROTECT_STOP_DATE
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Deactivation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.DEACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two Rekey
        request payloads with different types.
        """
        a = payloads.RekeyRequestPayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Rekey request payloads with the same data.
        """
        a = payloads.RekeyRequestPayload()
        b = payloads.RekeyRequestPayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.RekeyRequestPayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyRequestPayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Activation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1136113200,
                            tag=enums.Tags.ACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns True when comparing two Rekey
        request payloads with different unique identifiers.
        """
        a = payloads.RekeyRequestPayload(
            unique_identifier='a'
        )
        b = payloads.RekeyRequestPayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_offset(self):
        """
        Test that the inequality operator returns True when comparing two Rekey
        request payloads with different offsets.
        """
        a = payloads.RekeyRequestPayload(
            offset=0
        )
        b = payloads.RekeyRequestPayload(
            offset=1
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two Rekey
        request payloads with different template attributes.
        """
        a = payloads.RekeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Protect Stop Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.PROTECT_STOP_DATE
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyRequestPayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Deactivation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.DEACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two Rekey
        request payloads with different types.
        """
        a = payloads.RekeyRequestPayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Rekey request payload.
        """
        payload = payloads.RekeyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Deactivation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.DEACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        # TODO (peter-hamilton) Update this when TemplateAttributes have repr
        expected = (
            "RekeyRequestPayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "offset=0, "
            "template_attribute=Struct())"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Rekey request payload
        """
        payload = payloads.RekeyRequestPayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            offset=0,
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Deactivation Date'
                        ),
                        attribute_value=primitives.DateTime(
                            value=1577876400,
                            tag=enums.Tags.DEACTIVATION_DATE
                        )
                    )
                ]
            )
        )

        # TODO (peter-hamilton) Update this when TemplateAttributes have str
        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'offset': 0,
            'template_attribute': 'Struct()'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)

class TestRekeyResponsePayload(testtools.TestCase):
    """
    Test suite for the Rekey response payload.
    """

    def setUp(self):
        super(TestRekeyResponsePayload, self).setUp()

        # Encoding obtained from the KMIP 1.1 testing document,
        # Sections 3.1.1 and 9.2.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 8efbbd67-2847-46b5-b7e7-4ab3b5e175de
        #     Template Attribute
        #         Attribute
        #             Attribute Name - Cryptographic Algorithm
        #             Attribute Value - AES
        #         Attribute
        #             Attribute Name - Cryptographic Length
        #             Attribute Value - 128

        self.full_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\xA8'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x38\x65\x66\x62\x62\x64\x36\x37\x2D\x32\x38\x34\x37\x2D\x34\x36'
            b'\x62\x35\x2D\x62\x37\x65\x37\x2D\x34\x61\x62\x33\x62\x35\x65\x31'
            b'\x37\x35\x64\x65\x00\x00\x00\x00'
            b'\x42\x00\x91\x01\x00\x00\x00\x70'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x17'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x41\x6C'
            b'\x67\x6F\x72\x69\x74\x68\x6D\x00'
            b'\x42\x00\x0B\x05\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x00'
            b'\x42\x00\x08\x01\x00\x00\x00\x30'
            b'\x42\x00\x0A\x07\x00\x00\x00\x14'
            b'\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x4C\x65'
            b'\x6E\x67\x74\x68\x00\x00\x00\x00'
            b'\x42\x00\x0B\x02\x00\x00\x00\x04\x00\x00\x00\x80\x00\x00\x00\x00'
        )

        # Encoding obtained from the KMIP 1.1 testing document,
        # Sections 3.1.1 and 9.2.
        #
        # This encoding matches the following set of values:
        # Response Payload
        #     Unique Identifier - 8efbbd67-2847-46b5-b7e7-4ab3b5e175de

        self.partial_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x30'
            b'\x42\x00\x94\x07\x00\x00\x00\x24'
            b'\x38\x65\x66\x62\x62\x64\x36\x37\x2D\x32\x38\x34\x37\x2D\x34\x36'
            b'\x62\x35\x2D\x62\x37\x65\x37\x2D\x34\x61\x62\x33\x62\x35\x65\x31'
            b'\x37\x35\x64\x65\x00\x00\x00\x00'
        )

        self.empty_encoding = utils.BytearrayStream(
            b'\x42\x00\x7C\x01\x00\x00\x00\x00'
        )

    def tearDown(self):
        super(TestRekeyResponsePayload, self).tearDown()

    def test_init(self):
        """
        Test that a Rekey response payload can be constructed with no
        arguments.
        """
        payload = payloads.RekeyResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.template_attribute)

    def test_init_with_args(self):
        """
        Test that a Rekey response payload can be constructed with valid
        values.
        """
        payload = payloads.RekeyResponsePayload(
            unique_identifier='00000000-2222-4444-6666-888888888888',
            template_attribute=objects.TemplateAttribute()
        )

        self.assertEqual(
            '00000000-2222-4444-6666-888888888888',
            payload.unique_identifier
        )
        self.assertEqual(
            objects.TemplateAttribute(),
            payload.template_attribute
        )

    def test_invalid_unique_identifier(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the unique identifier of a Rekey response payload.
        """
        kwargs = {'unique_identifier': 0}
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            payloads.RekeyResponsePayload,
            **kwargs
        )

        args = (payloads.RekeyResponsePayload(), 'unique_identifier', 0)
        self.assertRaisesRegex(
            TypeError,
            "Unique identifier must be a string.",
            setattr,
            *args
        )

    def test_invalid_template_attribute(self):
        """
        Test that a TypeError is raised when an invalid value is used to set
        the template attribute of a Rekey response payload.
        """
        kwargs = {'template_attribute': 'invalid'}
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute struct.",
            payloads.RekeyResponsePayload,
            **kwargs
        )

        args = (
            payloads.RekeyResponsePayload(),
            'template_attribute',
            'invalid'
        )
        self.assertRaisesRegex(
            TypeError,
            "Template attribute must be a TemplateAttribute struct.",
            setattr,
            *args
        )

    def test_read(self):
        """
        Test that a Rekey response payload can be read from a data stream.
        """
        payload = payloads.RekeyResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.full_encoding)

        self.assertEqual(
            '8efbbd67-2847-46b5-b7e7-4ab3b5e175de',
            payload.unique_identifier
        )
        self.assertEqual(
            objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            ),
            payload.template_attribute
        )

    def test_read_partial(self):
        """
        Test that a Rekey response payload can be read from a partial data
        stream.
        """
        payload = payloads.RekeyResponsePayload()

        self.assertEqual(None, payload.unique_identifier)
        self.assertEqual(None, payload.template_attribute)

        payload.read(self.partial_encoding)

        self.assertEqual(
            '8efbbd67-2847-46b5-b7e7-4ab3b5e175de',
            payload.unique_identifier
        )
        self.assertEqual(None, payload.template_attribute)

    def test_read_invalid(self):
        """
        Test that a ValueError gets raised when a required Rekey response
        payload attribute is missing from the payload encoding.
        """
        payload = payloads.RekeyResponsePayload()
        args = (self.empty_encoding, )
        self.assertRaisesRegex(
            ValueError,
            "The Rekey response payload encoding is missing the unique "
            "identifier.",
            payload.read,
            *args
        )

    def test_write(self):
        """
        Test that a Rekey response payload can be written to a data stream.
        """
        payload = payloads.RekeyResponsePayload(
            unique_identifier='8efbbd67-2847-46b5-b7e7-4ab3b5e175de',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.full_encoding), len(stream))
        self.assertEqual(str(self.full_encoding), str(stream))

    def test_write_partial(self):
        """
        Test that a partial Rekey response payload can be written to a data
        stream.
        """
        payload = payloads.RekeyResponsePayload(
            unique_identifier='8efbbd67-2847-46b5-b7e7-4ab3b5e175de'
        )
        stream = utils.BytearrayStream()
        payload.write(stream)

        self.assertEqual(len(self.partial_encoding), len(stream))
        self.assertEqual(str(self.partial_encoding), str(stream))

    def test_write_invalid(self):
        """
        Test that a ValueError gets raised when a required Rekey response
        payload attribute is missing when encoding the payload.
        """
        payload = payloads.RekeyResponsePayload()
        stream = utils.BytearrayStream()
        args = (stream, )
        self.assertRaisesRegex(
            ValueError,
            "The Rekey response payload is missing the unique identifier.",
            payload.write,
            *args
        )

    def test_equal_on_equal(self):
        """
        Test that the equality operator returns True when comparing two Rekey
        response payloads with the same data.
        """
        a = payloads.RekeyResponsePayload()
        b = payloads.RekeyResponsePayload()

        self.assertTrue(a == b)
        self.assertTrue(b == a)

        a = payloads.RekeyResponsePayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyResponsePayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertTrue(a == b)
        self.assertTrue(b == a)

    def test_equal_on_not_equal_unique_identifier(self):
        """
        Test that the equality operator returns False when comparing two Rekey
        response payloads with different unique identifiers.
        """
        a = payloads.RekeyResponsePayload(
            unique_identifier='a'
        )
        b = payloads.RekeyResponsePayload(
            unique_identifier='b'
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_not_equal_template_attribute(self):
        """
        Test that the equality operator returns False when comparing two Rekey
        response payloads with different template attributes.
        """
        a = payloads.RekeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_equal_on_type_mismatch(self):
        """
        Test that the equality operator returns False when comparing two Rekey
        response payloads with different types.
        """
        a = payloads.RekeyResponsePayload()
        b = 'invalid'

        self.assertFalse(a == b)
        self.assertFalse(b == a)

    def test_not_equal_on_equal(self):
        """
        Test that the inequality operator returns False when comparing two
        Rekey response payloads with the same data.
        """
        a = payloads.RekeyResponsePayload()
        b = payloads.RekeyResponsePayload()

        self.assertFalse(a != b)
        self.assertFalse(b != a)

        a = payloads.RekeyResponsePayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyResponsePayload(
            unique_identifier='1346d253-69d6-474c-8cd5-ad475a3e0a81',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    ),
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertFalse(a != b)
        self.assertFalse(b != a)

    def test_not_equal_on_not_equal_unique_identifier(self):
        """
        Test that the inequality operator returns True when comparing two Rekey
        response payloads with different unique identifiers.
        """
        a = payloads.RekeyResponsePayload(
            unique_identifier='a'
        )
        b = payloads.RekeyResponsePayload(
            unique_identifier='b'
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_not_equal_template_attribute(self):
        """
        Test that the inequality operator returns True when comparing two Rekey
        response payloads with different template attributes.
        """
        a = payloads.RekeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Algorithm'
                        ),
                        attribute_value=primitives.Enumeration(
                            enums.CryptographicAlgorithm,
                            value=enums.CryptographicAlgorithm.AES,
                            tag=enums.Tags.CRYPTOGRAPHIC_ALGORITHM
                        )
                    )
                ]
            )
        )
        b = payloads.RekeyResponsePayload(
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_not_equal_on_type_mismatch(self):
        """
        Test that the inequality operator returns True when comparing two Rekey
        response payloads with different types.
        """
        a = payloads.RekeyResponsePayload()
        b = 'invalid'

        self.assertTrue(a != b)
        self.assertTrue(b != a)

    def test_repr(self):
        """
        Test that repr can be applied to a Rekey response payload.
        """
        payload = payloads.RekeyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        # TODO (peter-hamilton) Update this when TemplateAttributes have repr
        expected = (
            "RekeyResponsePayload("
            "unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038', "
            "template_attribute=Struct())"
        )
        observed = repr(payload)

        self.assertEqual(expected, observed)

    def test_str(self):
        """
        Test that str can be applied to a Rekey response payload
        """
        payload = payloads.RekeyResponsePayload(
            unique_identifier='49a1ca88-6bea-4fb2-b450-7e58802c3038',
            template_attribute=objects.TemplateAttribute(
                attributes=[
                    objects.Attribute(
                        attribute_name=objects.Attribute.AttributeName(
                            'Cryptographic Length'
                        ),
                        attribute_value=primitives.Integer(
                            value=128,
                            tag=enums.Tags.CRYPTOGRAPHIC_LENGTH
                        )
                    )
                ]
            )
        )

        # TODO (peter-hamilton) Update this when TemplateAttributes have str
        expected = str({
            'unique_identifier': '49a1ca88-6bea-4fb2-b450-7e58802c3038',
            'template_attribute': 'Struct()'
        })
        observed = str(payload)

        self.assertEqual(expected, observed)
