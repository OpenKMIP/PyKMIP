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

from kmip.core import attributes
from kmip.core import enums
from kmip.core import misc
from kmip.core import secrets
from kmip.core import objects as cobjects

from kmip.pie import factory
from kmip.pie import objects as pobjects

class TestObjectFactory(testtools.TestCase):
    """
    Test suite for the ObjectFactory.
    """

    def setUp(self):
        super(TestObjectFactory, self).setUp()
        self.factory = factory.ObjectFactory()

        # Key encoding obtained from Sections 3.1.5, 13.2, 13.4, and 14.2 of
        # the KMIP 1.1 test documentation.
        self.symmetric_bytes = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E'
            b'\x0F')
        self.public_bytes = (
            b'\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42\x49'
            b'\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00\x3A'
            b'\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00\x2C'
            b'\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D\x75'
            b'\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7\xEC'
            b'\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F\xA2'
            b'\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4\xBB'
            b'\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF\x8B'
            b'\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D\x57'
            b'\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC\xC8'
            b'\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7\xF4'
            b'\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D\x0C'
            b'\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE\x64'
            b'\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC\xE8'
            b'\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73\xA1'
            b'\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC\x41'
            b'\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01')
        self.private_bytes = (
            b'\x30\x82\x04\xA5\x02\x01\x00\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C'
            b'\x00\x42\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77'
            b'\x76\x00\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55'
            b'\xF8\x00\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48'
            b'\x34\x6D\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D'
            b'\x7D\xC7\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6'
            b'\x26\x7F\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5'
            b'\xA5\xF4\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49'
            b'\x00\xDF\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD'
            b'\xBC\x7D\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8'
            b'\xA0\xEC\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B'
            b'\xB8\xB7\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8'
            b'\xDA\x7D\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1'
            b'\xB7\xAE\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8'
            b'\xD7\xCC\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8'
            b'\x2D\x73\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29'
            b'\xC6\xFC\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00'
            b'\x01\x02\x82\x01\x00\x3B\x12\x45\x5D\x53\xC1\x81\x65\x16\xC5\x18'
            b'\x49\x3F\x63\x98\xAA\xFA\x72\xB1\x7D\xFA\x89\x4D\xB8\x88\xA7\xD4'
            b'\x8C\x0A\x47\xF6\x25\x79\xA4\xE6\x44\xF8\x6D\xA7\x11\xFE\xC8\x50'
            b'\xCD\xD9\xDB\xBD\x17\xF6\x9A\x44\x3D\x2E\xC1\xDD\x60\xD3\xC6\x18'
            b'\xFA\x74\xCD\xE5\xFD\xAF\xAB\xD6\xBA\xA2\x6E\xB0\xA3\xAD\xB4\xDE'
            b'\xF6\x48\x0F\xB1\x21\x8C\xD3\xB0\x83\xE2\x52\xE8\x85\xB6\xF0\x72'
            b'\x9F\x98\xB2\x14\x4D\x2B\x72\x29\x3E\x1B\x11\xD7\x33\x93\xBC\x41'
            b'\xF7\x5B\x15\xEE\x3D\x75\x69\xB4\x99\x5E\xD1\xA1\x44\x25\xDA\x43'
            b'\x19\xB7\xB2\x6B\x0E\x8F\xEF\x17\xC3\x75\x42\xAE\x5C\x6D\x58\x49'
            b'\xF8\x72\x09\x56\x7F\x39\x25\xA4\x7B\x01\x6D\x56\x48\x59\x71\x7B'
            b'\xC5\x7F\xCB\x45\x22\xD0\xAA\x49\xCE\x81\x6E\x5B\xE7\xB3\x08\x81'
            b'\x93\x23\x6E\xC9\xEF\xFF\x14\x08\x58\x04\x5B\x73\xC5\xD7\x9B\xAF'
            b'\x38\xF7\xC6\x7F\x04\xC5\xDC\xF0\xE3\x80\x6A\xD9\x82\xD1\x25\x90'
            b'\x58\xC3\x47\x3E\x84\x71\x79\xA8\x78\xF2\xC6\xB3\xBD\x96\x8F\xB9'
            b'\x9E\xA4\x6E\x91\x85\x89\x2F\x36\x76\xE7\x89\x65\xC2\xAE\xD4\x87'
            b'\x7B\xA3\x91\x7D\xF0\x7C\x5E\x92\x74\x74\xF1\x9E\x76\x4B\xA6\x1D'
            b'\xC3\x8D\x63\xBF\x29\x02\x81\x81\x00\xD5\xC6\x9C\x8C\x3C\xDC\x24'
            b'\x64\x74\x4A\x79\x37\x13\xDA\xFB\x9F\x1D\xBC\x79\x9F\xF9\x64\x23'
            b'\xFE\xCD\x3C\xBA\x79\x42\x86\xBC\xE9\x20\xF4\xB5\xC1\x83\xF9\x9E'
            b'\xE9\x02\x8D\xB6\x21\x2C\x62\x77\xC4\xC8\x29\x7F\xCF\xBC\xE7\xF7'
            b'\xC2\x4C\xA4\xC5\x1F\xC7\x18\x2F\xB8\xF4\x01\x9F\xB1\xD5\x65\x96'
            b'\x74\xC5\xCB\xE6\xD5\xFA\x99\x20\x51\x34\x17\x60\xCD\x00\x73\x57'
            b'\x29\xA0\x70\xA9\xE5\x4D\x34\x2B\xEB\xA8\xEF\x47\xEE\x82\xD3\xA0'
            b'\x1B\x04\xCE\xC4\xA0\x0D\x4D\xDB\x41\xE3\x51\x16\xFC\x22\x1E\x85'
            b'\x4B\x43\xA6\x96\xC0\xE6\x41\x9B\x1B\x02\x81\x81\x00\xCD\x5E\xA7'
            b'\x70\x27\x89\x06\x4B\x67\x35\x40\xCB\xFF\x09\x35\x6A\xD8\x0B\xC3'
            b'\xD5\x92\x81\x2E\xBA\x47\x61\x0B\x9F\xAC\x6A\xEC\xEF\xE2\x2A\xCA'
            b'\xE4\x38\x45\x9C\xDA\x74\xE5\x96\x53\xD8\x8C\x04\x18\x9D\x34\x39'
            b'\x9B\xF5\xB1\x4B\x92\x0E\x34\xEF\x38\xA7\xD0\x9F\xE6\x95\x93\x39'
            b'\x6E\x8F\xE7\x35\xE6\xF0\xA6\xAE\x49\x90\x40\x10\x41\xD8\xA4\x06'
            b'\xB6\xFD\x86\xA1\x16\x1E\x45\xF9\x5A\x3E\xAA\x5C\x10\x12\xE6\x66'
            b'\x2E\x44\xF1\x5F\x33\x5A\xC9\x71\xE1\x76\x6B\x2B\xB9\xC9\x85\x10'
            b'\x99\x74\x14\x1B\x44\xD3\x7E\x1E\x31\x98\x20\xA5\x5F\x02\x81\x81'
            b'\x00\xB2\x87\x12\x37\xBF\x9F\xAD\x38\xC3\x31\x6A\xB7\x87\x7A\x6A'
            b'\x86\x80\x63\xE5\x42\xA7\x18\x6D\x43\x1E\x8D\x27\xC1\x9A\xC0\x41'
            b'\x45\x84\x03\x39\x42\xE9\xFF\x6E\x29\x73\xBB\x7B\x2D\x8B\x0E\x94'
            b'\xAD\x1E\xE8\x21\x58\x10\x8F\xBC\x86\x64\x51\x7A\x5A\x46\x7F\xB9'
            b'\x63\x01\x4B\xD5\xDC\xC2\xB4\xFB\x08\x7C\x23\x03\x9D\x11\x92\x0D'
            b'\xBE\x22\xFD\x9F\x16\xB4\xD8\x9E\x23\x22\x5C\xD4\x55\xAD\xBA\xF3'
            b'\x2E\xF4\x3F\x18\x58\x64\xA3\x6D\x63\x03\x09\xD6\x85\x3F\x77\x14'
            b'\xB3\x9A\xAE\x1E\xBE\xE3\x93\x8F\x87\xC2\x70\x7E\x17\x8C\x73\x9F'
            b'\x9F\x02\x81\x81\x00\x96\x90\xBE\xD1\x4B\x2A\xFA\xA2\x6D\x98\x6D'
            b'\x59\x22\x31\xEE\x27\xD7\x1D\x49\x06\x5B\xD2\xBA\x1F\x78\x15\x7E'
            b'\x20\x22\x98\x81\xFD\x9D\x23\x22\x7D\x0F\x84\x79\xEA\xEF\xA9\x22'
            b'\xFD\x75\xD5\xB1\x6B\x1A\x56\x1F\xA6\x68\x0B\x04\x0C\xA0\xBD\xCE'
            b'\x65\x0B\x23\xB9\x17\xA4\xB1\xBB\x79\x83\xA7\x4F\xAD\x70\xE1\xC3'
            b'\x05\xCB\xEC\x2B\xFF\x1A\x85\xA7\x26\xA1\xD9\x02\x60\xE4\xF1\x08'
            b'\x4F\x51\x82\x34\xDC\xD3\xFE\x77\x0B\x95\x20\x21\x5B\xD5\x43\xBB'
            b'\x6A\x41\x17\x71\x87\x54\x67\x6A\x34\x17\x16\x66\xA7\x9F\x26\xE7'
            b'\x9C\x14\x9C\x5A\xA1\x02\x81\x81\x00\xA0\xC9\x85\xA0\xA0\xA7\x91'
            b'\xA6\x59\xF9\x97\x31\x13\x4C\x44\xF3\x7B\x2E\x52\x0A\x2C\xEA\x35'
            b'\x80\x0A\xD2\x72\x41\xED\x36\x0D\xFD\xE6\xE8\xCA\x61\x4F\x12\x04'
            b'\x7F\xD0\x8B\x76\xAC\x4D\x13\xC0\x56\xA0\x69\x9E\x2F\x98\xA1\xCA'
            b'\xC9\x10\x11\x29\x4D\x71\x20\x8F\x4A\xBA\xB3\x3B\xA8\x7A\xA0\x51'
            b'\x7F\x41\x5B\xAC\xA8\x8D\x6B\xAC\x00\x60\x88\xFA\x60\x1D\x34\x94'
            b'\x17\xE1\xF0\xC9\xB2\x3A\xFF\xA4\xD4\x96\x61\x8D\xBC\x02\x49\x86'
            b'\xED\x69\x0B\xBB\x7B\x02\x57\x68\xFF\x9D\xF8\xAC\x15\x41\x6F\x48'
            b'\x9F\x81\x29\xC3\x23\x41\xA8\xB4\x4F')
        self.certificate_bytes = (
            b'\x30\x82\x03\x12\x30\x82\x01\xFA\xA0\x03\x02\x01\x02\x02\x01\x01'
            b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00\x30'
            b'\x3B\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D'
            b'\x30\x0B\x06\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30'
            b'\x0C\x06\x03\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30'
            b'\x0B\x06\x03\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x1E\x17\x0D'
            b'\x31\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x17\x0D\x32'
            b'\x30\x31\x31\x30\x31\x32\x33\x35\x39\x35\x39\x5A\x30\x3B\x31\x0B'
            b'\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0D\x30\x0B\x06'
            b'\x03\x55\x04\x0A\x13\x04\x54\x45\x53\x54\x31\x0E\x30\x0C\x06\x03'
            b'\x55\x04\x0B\x13\x05\x4F\x41\x53\x49\x53\x31\x0D\x30\x0B\x06\x03'
            b'\x55\x04\x03\x13\x04\x4B\x4D\x49\x50\x30\x82\x01\x22\x30\x0D\x06'
            b'\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F'
            b'\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00\xAB\x7F\x16\x1C\x00\x42'
            b'\x49\x6C\xCD\x6C\x6D\x4D\xAD\xB9\x19\x97\x34\x35\x35\x77\x76\x00'
            b'\x3A\xCF\x54\xB7\xAF\x1E\x44\x0A\xFB\x80\xB6\x4A\x87\x55\xF8\x00'
            b'\x2C\xFE\xBA\x6B\x18\x45\x40\xA2\xD6\x60\x86\xD7\x46\x48\x34\x6D'
            b'\x75\xB8\xD7\x18\x12\xB2\x05\x38\x7C\x0F\x65\x83\xBC\x4D\x7D\xC7'
            b'\xEC\x11\x4F\x3B\x17\x6B\x79\x57\xC4\x22\xE7\xD0\x3F\xC6\x26\x7F'
            b'\xA2\xA6\xF8\x9B\x9B\xEE\x9E\x60\xA1\xD7\xC2\xD8\x33\xE5\xA5\xF4'
            b'\xBB\x0B\x14\x34\xF4\xE7\x95\xA4\x11\x00\xF8\xAA\x21\x49\x00\xDF'
            b'\x8B\x65\x08\x9F\x98\x13\x5B\x1C\x67\xB7\x01\x67\x5A\xBD\xBC\x7D'
            b'\x57\x21\xAA\xC9\xD1\x4A\x7F\x08\x1F\xCE\xC8\x0B\x64\xE8\xA0\xEC'
            b'\xC8\x29\x53\x53\xC7\x95\x32\x8A\xBF\x70\xE1\xB4\x2E\x7B\xB8\xB7'
            b'\xF4\xE8\xAC\x8C\x81\x0C\xDB\x66\xE3\xD2\x11\x26\xEB\xA8\xDA\x7D'
            b'\x0C\xA3\x41\x42\xCB\x76\xF9\x1F\x01\x3D\xA8\x09\xE9\xC1\xB7\xAE'
            b'\x64\xC5\x41\x30\xFB\xC2\x1D\x80\xE9\xC2\xCB\x06\xC5\xC8\xD7\xCC'
            b'\xE8\x94\x6A\x9A\xC9\x9B\x1C\x28\x15\xC3\x61\x2A\x29\xA8\x2D\x73'
            b'\xA1\xF9\x93\x74\xFE\x30\xE5\x49\x51\x66\x2A\x6E\xDA\x29\xC6\xFC'
            b'\x41\x13\x35\xD5\xDC\x74\x26\xB0\xF6\x05\x02\x03\x01\x00\x01\xA3'
            b'\x21\x30\x1F\x30\x1D\x06\x03\x55\x1D\x0E\x04\x16\x04\x14\x04\xE5'
            b'\x7B\xD2\xC4\x31\xB2\xE8\x16\xE1\x80\xA1\x98\x23\xFA\xC8\x58\x27'
            b'\x3F\x6B\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05'
            b'\x00\x03\x82\x01\x01\x00\xA8\x76\xAD\xBC\x6C\x8E\x0F\xF0\x17\x21'
            b'\x6E\x19\x5F\xEA\x76\xBF\xF6\x1A\x56\x7C\x9A\x13\xDC\x50\xD1\x3F'
            b'\xEC\x12\xA4\x27\x3C\x44\x15\x47\xCF\xAB\xCB\x5D\x61\xD9\x91\xE9'
            b'\x66\x31\x9D\xF7\x2C\x0D\x41\xBA\x82\x6A\x45\x11\x2F\xF2\x60\x89'
            b'\xA2\x34\x4F\x4D\x71\xCF\x7C\x92\x1B\x4B\xDF\xAE\xF1\x60\x0D\x1B'
            b'\xAA\xA1\x53\x36\x05\x7E\x01\x4B\x8B\x49\x6D\x4F\xAE\x9E\x8A\x6C'
            b'\x1D\xA9\xAE\xB6\xCB\xC9\x60\xCB\xF2\xFA\xE7\x7F\x58\x7E\xC4\xBB'
            b'\x28\x20\x45\x33\x88\x45\xB8\x8D\xD9\xAE\xEA\x53\xE4\x82\xA3\x6E'
            b'\x73\x4E\x4F\x5F\x03\xB9\xD0\xDF\xC4\xCA\xFC\x6B\xB3\x4E\xA9\x05'
            b'\x3E\x52\xBD\x60\x9E\xE0\x1E\x86\xD9\xB0\x9F\xB5\x11\x20\xC1\x98'
            b'\x34\xA9\x97\xB0\x9C\xE0\x8D\x79\xE8\x13\x11\x76\x2F\x97\x4B\xB1'
            b'\xC8\xC0\x91\x86\xC4\xD7\x89\x33\xE0\xDB\x38\xE9\x05\x08\x48\x77'
            b'\xE1\x47\xC7\x8A\xF5\x2F\xAE\x07\x19\x2F\xF1\x66\xD1\x9F\xA9\x4A'
            b'\x11\xCC\x11\xB2\x7E\xD0\x50\xF7\xA2\x7F\xAE\x13\xB2\x05\xA5\x74'
            b'\xC4\xEE\x00\xAA\x8B\xD6\x5D\x0D\x70\x57\xC9\x85\xC8\x39\xEF\x33'
            b'\x6A\x44\x1E\xD5\x3A\x53\xC6\xB6\xB6\x96\xF1\xBD\xEB\x5F\x7E\xA8'
            b'\x11\xEB\xB2\x5A\x7F\x86')
        self.secret_bytes = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64')
        self.opaque_bytes = (
            b'\x53\x65\x63\x72\x65\x74\x50\x61\x73\x73\x77\x6F\x72\x64')

    def tearDown(self):
        super(TestObjectFactory, self).tearDown()

    def test_init(self):
        """
        Test that an ObjectFactory can be constructed.
        """
        factory.ObjectFactory()

    def test_convert_on_invalid(self):
        """
        Test that a TypeError is raised when an invalid object is given to the
        convert method.
        """
        f = factory.ObjectFactory()
        self.assertRaises(TypeError, f.convert, 'invalid')

    def test_convert_symmetric_key_pie_to_core(self):
        """
        Test that a Pie symmetric key can be converted into a core symmetric
        key.
        """
        pie_key = pobjects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.symmetric_bytes)

        core_key = self.factory.convert(pie_key)
        self.assertIsInstance(core_key, secrets.SymmetricKey)
        self._test_core_key(
            core_key, enums.CryptographicAlgorithm.AES, 128,
            self.symmetric_bytes, enums.KeyFormatType.RAW)

    def test_convert_symmetric_key_core_to_pie(self):
        """
        Test that a core symmetric key can be converted into a Pie symmetric
        key.
        """
        format_type = misc.KeyFormatType(enums.KeyFormatType.RAW)
        algorithm = attributes.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.AES)
        length = attributes.CryptographicLength(128)
        key_material = cobjects.KeyMaterial(self.symmetric_bytes)
        key_value = cobjects.KeyValue(key_material)
        key_block = cobjects.KeyBlock(
            key_format_type=format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=algorithm,
            cryptographic_length=length,
            key_wrapping_data=None)
        core_key = secrets.SymmetricKey(key_block)

        pie_key = self.factory.convert(core_key)
        self.assertIsInstance(pie_key, pobjects.SymmetricKey)
        self._test_pie_key(
            pie_key, algorithm.value, length.value, self.symmetric_bytes,
            format_type.value)

    def test_convert_public_key_pie_to_core(self):
        """
        Test that a Pie public key can be converted into a core public key.
        """
        pie_key = pobjects.PublicKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.public_bytes,
            enums.KeyFormatType.PKCS_1)

        core_key = self.factory.convert(pie_key)
        self.assertIsInstance(core_key, secrets.PublicKey)
        self._test_core_key(
            core_key, enums.CryptographicAlgorithm.RSA, 2048,
            self.public_bytes, enums.KeyFormatType.PKCS_1)

    def test_convert_public_key_core_to_pie(self):
        """
        Test that a core public key can be converted into a Pie public key.
        """
        format_type = misc.KeyFormatType(enums.KeyFormatType.PKCS_1)
        algorithm = attributes.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.RSA)
        length = attributes.CryptographicLength(2048)
        key_material = cobjects.KeyMaterial(self.public_bytes)
        key_value = cobjects.KeyValue(key_material)
        key_block = cobjects.KeyBlock(
            key_format_type=format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=algorithm,
            cryptographic_length=length,
            key_wrapping_data=None)
        core_key = secrets.PublicKey(key_block)

        pie_key = self.factory.convert(core_key)
        self.assertIsInstance(pie_key, pobjects.PublicKey)
        self._test_pie_key(
            pie_key, algorithm.value, length.value, self.public_bytes,
            format_type.value)

    def test_convert_private_key_pie_to_core(self):
        """
        Test that a Pie private key can be converted into a core private key.
        """
        pie_key = pobjects.PrivateKey(
            enums.CryptographicAlgorithm.RSA, 2048, self.private_bytes,
            enums.KeyFormatType.PKCS_8)

        core_key = self.factory.convert(pie_key)
        self.assertIsInstance(core_key, secrets.PrivateKey)
        self._test_core_key(
            core_key, enums.CryptographicAlgorithm.RSA, 2048,
            self.private_bytes, enums.KeyFormatType.PKCS_8)

    def test_convert_private_key_core_to_pie(self):
        """
        Test that a core private key can be converted into a Pie private key.
        """
        format_type = misc.KeyFormatType(enums.KeyFormatType.PKCS_8)
        algorithm = attributes.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.RSA)
        length = attributes.CryptographicLength(2048)
        key_material = cobjects.KeyMaterial(self.private_bytes)
        key_value = cobjects.KeyValue(key_material)
        key_block = cobjects.KeyBlock(
            key_format_type=format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=algorithm,
            cryptographic_length=length,
            key_wrapping_data=None)
        core_key = secrets.PrivateKey(key_block)

        pie_key = self.factory.convert(core_key)
        self.assertIsInstance(pie_key, pobjects.PrivateKey)
        self._test_pie_key(
            pie_key, algorithm.value, length.value, self.private_bytes,
            format_type.value)

    def test_convert_certificate_pie_to_core(self):
        """
        Test that a Pie certificate can be converted into a core certificate.
        """
        pie_cert = pobjects.X509Certificate(self.certificate_bytes)
        core_cert = self.factory.convert(pie_cert)

        self.assertIsInstance(core_cert, secrets.Certificate)
        self.assertEqual(
            pie_cert.certificate_type, core_cert.certificate_type.value)
        self.assertEqual(pie_cert.value, core_cert.certificate_value.value)

    def test_convert_certificate_core_to_pie(self):
        """
        Test that a core certificate can be converted into a Pie certificate.
        """
        core_cert = secrets.Certificate(
            enums.CertificateType.X_509, self.certificate_bytes)
        pie_cert = self.factory.convert(core_cert)

        self.assertIsInstance(pie_cert, pobjects.X509Certificate)
        self.assertEqual(
            core_cert.certificate_type.value, pie_cert.certificate_type)
        self.assertEqual(core_cert.certificate_value.value, pie_cert.value)

    def test_convert_secret_data_pie_to_core(self):
        """
        Test that a Pie secret data object can be converted into a core secret
        data object.
        """
        pie_secret = pobjects.SecretData(
            self.secret_bytes, enums.SecretDataType.PASSWORD)
        core_secret = self.factory.convert(pie_secret)

        self.assertIsInstance(core_secret, secrets.SecretData)

        data_type = core_secret.secret_data_type.value
        self.assertEqual(enums.SecretDataType.PASSWORD, data_type)

        key_block = core_secret.key_block
        self.assertIsInstance(key_block, cobjects.KeyBlock)

        key_value = key_block.key_value
        self.assertIsInstance(key_value, cobjects.KeyValue)

        key_material = key_value.key_material
        self.assertIsInstance(key_material, cobjects.KeyMaterial)
        self.assertEqual(self.secret_bytes, key_material.value)

    def test_convert_secret_data_core_to_pie(self):
        """
        Test that a core secret data object can be converted into a Pie secret
        data object.
        """
        format_type = misc.KeyFormatType(enums.KeyFormatType.OPAQUE)
        key_material = cobjects.KeyMaterial(self.secret_bytes)
        key_value = cobjects.KeyValue(key_material)
        key_block = cobjects.KeyBlock(
            key_format_type=format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=None,
            cryptographic_length=None,
            key_wrapping_data=None)
        data_type = secrets.SecretData.SecretDataType(
            enums.SecretDataType.PASSWORD)
        core_key = secrets.SecretData(data_type, key_block)

        pie_key = self.factory.convert(core_key)
        self.assertIsInstance(pie_key, pobjects.SecretData)
        self.assertEqual(enums.SecretDataType.PASSWORD, pie_key.data_type)
        self.assertEqual(self.secret_bytes, pie_key.value)

    def test_convert_opaque_object_pie_to_core(self):
        """
        Test that a Pie opaque object can be converted into a core opaque
        object.
        """
        pie_obj = pobjects.OpaqueObject(
            self.opaque_bytes, enums.OpaqueDataType.NONE)
        core_obj = self.factory.convert(pie_obj)

        self.assertIsInstance(core_obj, secrets.OpaqueObject)

        opaque_type = core_obj.opaque_data_type.value
        self.assertEqual(enums.OpaqueDataType.NONE, opaque_type)

        value = core_obj.opaque_data_value.value
        self.assertEqual(self.opaque_bytes, value)

    def test_convert_opaque_object_core_to_pie(self):
        """
        Test that a core opaque object can be converted into a Pie opaque
        object.
        """
        opaque_data_type = secrets.OpaqueObject.OpaqueDataType(
            enums.OpaqueDataType.NONE)
        opaque_data_value = secrets.OpaqueObject.OpaqueDataValue(
            self.opaque_bytes)
        core_obj = secrets.OpaqueObject(opaque_data_type, opaque_data_value)
        pie_obj = self.factory.convert(core_obj)

        self.assertIsInstance(pie_obj, pobjects.OpaqueObject)
        self.assertEqual(enums.OpaqueDataType.NONE, pie_obj.opaque_type)
        self.assertEqual(self.opaque_bytes, pie_obj.value)

    def test_convert_split_key_pie_to_core(self):
        """
        Test that a Pie split key object can be converted into a core split
        key object.
        """
        pie_split_key = pobjects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=self.symmetric_bytes,
            cryptographic_usage_masks=[enums.CryptographicUsageMask.EXPORT],
            name="Split Key",
            key_format_type=enums.KeyFormatType.RAW,
            key_wrapping_data=None,
            split_key_parts=3,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.XOR,
            prime_field_size=None
        )
        core_split_key = self.factory.convert(pie_split_key)

        self.assertIsInstance(core_split_key, secrets.SplitKey)
        self._test_core_key(
            core_split_key,
            enums.CryptographicAlgorithm.AES,
            128,
            self.symmetric_bytes,
            enums.KeyFormatType.RAW
        )
        self.assertEqual(3, core_split_key.split_key_parts)
        self.assertEqual(1, core_split_key.key_part_identifier)
        self.assertEqual(2, core_split_key.split_key_threshold)
        self.assertEqual(
            enums.SplitKeyMethod.XOR,
            core_split_key.split_key_method
        )
        self.assertIsNone(core_split_key.prime_field_size)

    def test_convert_split_key_core_to_pie(self):
        """
        Test that a core split key object can be converted into a Pie split
        key object.
        """
        key_block = cobjects.KeyBlock(
            key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
            key_compression_type=None,
            key_value=cobjects.KeyValue(
                cobjects.KeyMaterial(self.symmetric_bytes)
            ),
            cryptographic_algorithm=attributes.CryptographicAlgorithm(
                enums.CryptographicAlgorithm.AES
            ),
            cryptographic_length=attributes.CryptographicLength(128),
            key_wrapping_data=None
        )
        core_split_key = secrets.SplitKey(
            split_key_parts=3,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.XOR,
            prime_field_size=None,
            key_block=key_block
        )
        pie_split_key = self.factory.convert(core_split_key)

        self.assertIsInstance(pie_split_key, pobjects.SplitKey)
        self._test_pie_key(
            pie_split_key,
            enums.CryptographicAlgorithm.AES,
            128,
            self.symmetric_bytes,
            enums.KeyFormatType.RAW
        )
        self.assertEqual(3, pie_split_key.split_key_parts)
        self.assertEqual(1, pie_split_key.key_part_identifier)
        self.assertEqual(2, pie_split_key.split_key_threshold)
        self.assertEqual(
            enums.SplitKeyMethod.XOR,
            pie_split_key.split_key_method
        )
        self.assertIsNone(pie_split_key.prime_field_size)

    def test_build_pie_symmetric_key(self):
        """
        Test that a core SymmetricKey object can be converted into a Pie
        SymmetricKey object.
        """
        format_type = misc.KeyFormatType(enums.KeyFormatType.RAW)
        algorithm = attributes.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.AES)
        length = attributes.CryptographicLength(128)
        key_material = cobjects.KeyMaterial(self.symmetric_bytes)
        key_value = cobjects.KeyValue(key_material)
        key_block = cobjects.KeyBlock(
            key_format_type=format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=algorithm,
            cryptographic_length=length,
            key_wrapping_data=None)
        core_key = secrets.SymmetricKey(key_block)
        pie_key = self.factory._build_pie_key(core_key, pobjects.SymmetricKey)

        self.assertIsInstance(pie_key, pobjects.SymmetricKey)
        self._test_pie_key(
            pie_key, algorithm.value, length.value, self.symmetric_bytes,
            format_type.value)

    def test_build_pie_symmetric_key_on_invalid_format(self):
        """
        Test that a TypeError exception is raised when attempting to create a
        Pie SymmetricKey object from a core SymmetricKey object with an
        incompatible format.
        """
        format_type = misc.KeyFormatType(enums.KeyFormatType.OPAQUE)
        algorithm = attributes.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.AES)
        length = attributes.CryptographicLength(128)
        key_material = cobjects.KeyMaterial(self.symmetric_bytes)
        key_value = cobjects.KeyValue(key_material)
        key_block = cobjects.KeyBlock(
            key_format_type=format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=algorithm,
            cryptographic_length=length,
            key_wrapping_data=None)
        core_key = secrets.SymmetricKey(key_block)

        args = [core_key, pobjects.SymmetricKey]
        self.assertRaises(TypeError, self.factory._build_pie_key, *args)

    def test_build_pie_asymmetric_key(self):
        """
        Test that a core asymmetric key object can be converted into a Pie
        asymmetric object.
        """
        format_type = misc.KeyFormatType(enums.KeyFormatType.PKCS_1)
        algorithm = attributes.CryptographicAlgorithm(
            enums.CryptographicAlgorithm.RSA)
        length = attributes.CryptographicLength(2048)
        key_material = cobjects.KeyMaterial(self.public_bytes)
        key_value = cobjects.KeyValue(key_material)
        key_block = cobjects.KeyBlock(
            key_format_type=format_type,
            key_compression_type=None,
            key_value=key_value,
            cryptographic_algorithm=algorithm,
            cryptographic_length=length,
            key_wrapping_data=None)
        core_key = secrets.PublicKey(key_block)
        pie_key = self.factory._build_pie_key(core_key, pobjects.PublicKey)

        self.assertIsInstance(pie_key, pobjects.PublicKey)
        self._test_pie_key(
            pie_key, algorithm.value, length.value, self.public_bytes,
            format_type.value)

    def test_build_core_key(self):
        """
        Test that a Pie key object can be converted into a core key object.
        """
        pie_key = pobjects.SymmetricKey(
            enums.CryptographicAlgorithm.AES, 128, self.symmetric_bytes)
        core_key = self.factory._build_core_key(pie_key, secrets.SymmetricKey)

        self.assertIsInstance(core_key, secrets.SymmetricKey)
        self._test_core_key(
            core_key, enums.CryptographicAlgorithm.AES, 128,
            self.symmetric_bytes, enums.KeyFormatType.RAW)

    def test_build_pie_certificate_on_invalid_type(self):
        """
        Test that a TypeError exception is raised when attempting to create a
        Pie Certificate object from a core Certificate object with an
        unsupported certificate type.
        """
        core_cert = secrets.Certificate(
            enums.CertificateType.PGP, self.certificate_bytes)
        args = (core_cert, )
        self.assertRaises(
            TypeError, self.factory._build_pie_certificate, *args)

    def test_build_core_split_key(self):
        """
        Test that a Pie split key object can be converted into a core key
        object.
        """
        pie_split_key = pobjects.SplitKey(
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            cryptographic_length=128,
            key_value=self.symmetric_bytes,
            cryptographic_usage_masks=[enums.CryptographicUsageMask.EXPORT],
            name="Split Key",
            key_format_type=enums.KeyFormatType.RAW,
            key_wrapping_data=None,
            split_key_parts=3,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.XOR,
            prime_field_size=None
        )
        core_split_key = self.factory._build_core_split_key(pie_split_key)

        self.assertIsInstance(core_split_key, secrets.SplitKey)
        self._test_core_key(
            core_split_key,
            enums.CryptographicAlgorithm.AES,
            128,
            self.symmetric_bytes,
            enums.KeyFormatType.RAW
        )
        self.assertEqual(3, core_split_key.split_key_parts)
        self.assertEqual(1, core_split_key.key_part_identifier)
        self.assertEqual(2, core_split_key.split_key_threshold)
        self.assertEqual(
            enums.SplitKeyMethod.XOR,
            core_split_key.split_key_method
        )
        self.assertIsNone(core_split_key.prime_field_size)

    def test_build_pie_split_key(self):
        """
        Test that a core split key object can be converted into a Pie split
        key object.
        """
        key_block = cobjects.KeyBlock(
            key_format_type=misc.KeyFormatType(enums.KeyFormatType.RAW),
            key_compression_type=None,
            key_value=cobjects.KeyValue(
                cobjects.KeyMaterial(self.symmetric_bytes)
            ),
            cryptographic_algorithm=attributes.CryptographicAlgorithm(
                enums.CryptographicAlgorithm.AES
            ),
            cryptographic_length=attributes.CryptographicLength(128),
            key_wrapping_data=None
        )
        core_split_key = secrets.SplitKey(
            split_key_parts=3,
            key_part_identifier=1,
            split_key_threshold=2,
            split_key_method=enums.SplitKeyMethod.XOR,
            prime_field_size=None,
            key_block=key_block
        )
        pie_split_key = self.factory._build_pie_split_key(core_split_key)

        self.assertIsInstance(pie_split_key, pobjects.SplitKey)
        self._test_pie_key(
            pie_split_key,
            enums.CryptographicAlgorithm.AES,
            128,
            self.symmetric_bytes,
            enums.KeyFormatType.RAW
        )
        self.assertEqual(3, pie_split_key.split_key_parts)
        self.assertEqual(1, pie_split_key.key_part_identifier)
        self.assertEqual(2, pie_split_key.split_key_threshold)
        self.assertEqual(
            enums.SplitKeyMethod.XOR,
            pie_split_key.split_key_method
        )
        self.assertIsNone(pie_split_key.prime_field_size)

    def _test_core_key(self, key, algorithm, length, value, format_type):
        key_block = key.key_block
        self.assertIsInstance(key_block, cobjects.KeyBlock)

        key_format_type = key_block.key_format_type
        self.assertIsInstance(key_format_type, misc.KeyFormatType)
        self.assertEqual(key_format_type.value, format_type)

        cryptographic_algorithm = key_block.cryptographic_algorithm
        self.assertIsInstance(
            cryptographic_algorithm, attributes.CryptographicAlgorithm)
        self.assertEqual(
            cryptographic_algorithm.value, algorithm)

        cryptographic_length = key_block.cryptographic_length
        self.assertIsInstance(
            cryptographic_length, attributes.CryptographicLength)
        self.assertEqual(cryptographic_length.value, length)

        key_value = key_block.key_value
        self.assertIsInstance(key_value, cobjects.KeyValue)

        key_material = key_value.key_material
        self.assertIsInstance(key_material, cobjects.KeyMaterial)
        self.assertEqual(key_material.value, value)

    def _test_pie_key(self, key, algorithm, length, value, format_type):
        self.assertEqual(key.cryptographic_algorithm, algorithm)
        self.assertEqual(key.cryptographic_length, length)
        self.assertEqual(key.key_format_type, format_type)
        self.assertEqual(key.value, value)

    def test_build_cryptographic_parameters(self):
        cryptographic_parameters = cobjects.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CBC,
            padding_method=enums.PaddingMethod.ANSI_X923,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            key_role_type=enums.KeyRoleType.KEK,
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.
            DSA_WITH_SHA1,
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,
            random_iv=True,
            iv_length=32,
            tag_length=33,
            fixed_field_length=34,
            invocation_field_length=35,
            counter_length=36,
            initial_counter_value=0
        )

        result = self.factory._build_cryptographic_parameters(
            cryptographic_parameters
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(
            enums.BlockCipherMode.CBC,
            result.get('block_cipher_mode')
        )
        self.assertEqual(
            enums.PaddingMethod.ANSI_X923,
            result.get('padding_method')
        )
        self.assertEqual(
            enums.HashingAlgorithm.SHA_256,
            result.get('hashing_algorithm')
        )
        self.assertEqual(
            enums.KeyRoleType.KEK,
            result.get('key_role_type')
        )
        self.assertEqual(
            enums.DigitalSignatureAlgorithm.DSA_WITH_SHA1,
            result.get('digital_signature_algorithm')
        )
        self.assertEqual(
            enums.CryptographicAlgorithm.AES,
            result.get('cryptographic_algorithm')
        )
        self.assertEqual(True, result.get('random_iv'))
        self.assertEqual(32, result.get('iv_length'))
        self.assertEqual(33, result.get('tag_length'))
        self.assertEqual(34, result.get('fixed_field_length'))
        self.assertEqual(35, result.get('invocation_field_length'))
        self.assertEqual(36, result.get('counter_length'))
        self.assertEqual(0, result.get('initial_counter_value'))

    def test_build_key_wrapping_data(self):
        key_wrapping_data = cobjects.KeyWrappingData(
            wrapping_method=enums.WrappingMethod.ENCRYPT,
            encryption_key_information=cobjects.EncryptionKeyInformation(
                unique_identifier='1',
                cryptographic_parameters=cobjects.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CBC
                )
            ),
            mac_signature_key_information=cobjects.MACSignatureKeyInformation(
                unique_identifier='2',
                cryptographic_parameters=cobjects.CryptographicParameters(
                    block_cipher_mode=enums.BlockCipherMode.CCM
                )
            ),
            mac_signature=b'\x01',
            iv_counter_nonce=b'\x02',
            encoding_option=enums.EncodingOption.NO_ENCODING
        )

        result = self.factory._build_key_wrapping_data(
            key_wrapping_data
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(
            enums.WrappingMethod.ENCRYPT,
            result.get('wrapping_method')
        )
        self.assertIsInstance(result.get('encryption_key_information'), dict)
        eki = result.get('encryption_key_information')
        self.assertEqual('1', eki.get('unique_identifier'))
        self.assertIsInstance(eki.get('cryptographic_parameters'), dict)
        self.assertIsInstance(
            result.get('mac_signature_key_information'),
            dict
        )
        mski = result.get('mac_signature_key_information')
        self.assertEqual('2', mski.get('unique_identifier'))
        self.assertIsInstance(mski.get('cryptographic_parameters'), dict)
        self.assertEqual(b'\x01', result.get('mac_signature'))
        self.assertEqual(b'\x02', result.get('iv_counter_nonce'))
        self.assertEqual(
            enums.EncodingOption.NO_ENCODING,
            result.get('encoding_option')
        )
