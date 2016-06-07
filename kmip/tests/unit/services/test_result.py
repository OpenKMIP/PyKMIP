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

from kmip.core.objects import Attribute
from kmip.core.factories.attributes import AttributeFactory

from kmip.core import enums
from kmip.services import results

from kmip.core.messages.contents import ResultStatus
from kmip.core.messages.contents import ResultReason
from kmip.core.messages.contents import ResultMessage


class TestServiceResult(TestCase):

    def setUp(self):
        super(TestServiceResult, self).setUp()

        self.uid = '3'
        self.attr_factory = AttributeFactory()
        self.attr_contact_information = self.attr_factory.create_attribute(
            enums.AttributeType.CONTACT_INFORMATION,
            'https://github.com/OpenKMIP/PyKMIP')

        self.status_success = ResultStatus(enums.ResultStatus.SUCCESS)
        self.status_failed = ResultStatus(enums.ResultStatus.OPERATION_FAILED)
        self.reason_not_found = ResultReason(enums.ResultReason.ITEM_NOT_FOUND)
        self.message = ResultMessage("message")
        self.invalid = 'invalid'

    def tearDown(self):
        super(TestServiceResult, self).tearDown()

    def test_add_attribute_init_with_success(self):
        result = results.AddAttributeResult(
            self.status_success,
            result_reason=None,
            result_message=None,
            uid=self.uid,
            attribute=self.attr_contact_information)

        self.assertIsInstance(result, results.AddAttributeResult)
        self.assertEqual(result.result_status, self.status_success)
        self.assertIsNone(result.result_reason)
        self.assertIsNone(result.result_message)
        self.assertEqual(result.uid, self.uid)
        self.assertIsInstance(result.attribute, Attribute)

    def test_add_attribute_init_with_failure(self):
        result = results.AddAttributeResult(
            self.status_failed,
            result_reason=self.reason_not_found,
            result_message=self.message)

        self.assertIsInstance(result, results.AddAttributeResult)
        self.assertEqual(result.result_status, self.status_failed)
        self.assertEqual(result.result_reason, self.reason_not_found)
        self.assertEqual(result.result_message, self.message)

    def test_add_attribute_validate_fails_on_status(self):
        error_msg = (
            "Invalid ResultStatus type; expected {0}; observed {1}".format(
                ResultStatus, type(self.invalid)))
        args = [self.invalid]
        self.assertRaisesRegexp(TypeError, error_msg,
                                results.AddAttributeResult, *args)

    def test_add_attribute_validate_fails_on_reason_invalid(self):
        error_msg = (
            "Invalid ResultReason type; expected {0}; observed {1}".format(
                ResultReason, type(self.invalid)))
        args = [self.status_failed]
        kwargs = {'result_reason': self.invalid}
        self.assertRaisesRegexp(TypeError, error_msg,
                                results.AddAttributeResult, *args, **kwargs)

    def test_add_attribute_validate_fails_on_reason_none(self):
        error_msg = (
            "ResultReason is mandatory for the non "
            "SUCCESS ResultStatus")
        args = [self.status_failed]
        self.assertRaisesRegexp(TypeError, error_msg,
                                results.AddAttributeResult, *args)

    def test_add_attribute_validate_fails_on_message(self):
        error_msg = (
            "Invalid ResultMessage type; expected {0}; observed {1}".format(
                ResultMessage, type(self.invalid)))
        args = [self.status_failed]
        kwargs = {
            'result_reason': self.reason_not_found,
            'result_message': self.invalid}
        self.assertRaisesRegexp(TypeError, error_msg,
                                results.AddAttributeResult, *args, **kwargs)

    def test_add_attribute_validate_fails_on_uid(self):
        error_msg = "UID is mandatory for result with SUCCESS status"
        args = [self.status_success]
        self.assertRaisesRegexp(TypeError, error_msg,
                                results.AddAttributeResult, *args)

    def test_add_attribute_validate_fails_on_attribute(self):
        error_msg = "Attribute is mandatory for result with SUCCESS status"
        args = [self.status_success]
        kwargs = {'uid': self.uid}
        self.assertRaisesRegexp(TypeError, error_msg,
                                results.AddAttributeResult, *args, **kwargs)
