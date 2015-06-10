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

# This module defines classes representing all of the different key types
# used by KMIP, including the more detailed structures of the Transparent
# Keys defined in Section 2.1.7.

from kmip.core.enums import Tags

from kmip.core.primitives import Struct
from kmip.core.primitives import ByteString

from kmip.core.utils import BytearrayStream


class RawKey(ByteString):

    def __init__(self, value=None):
        super(RawKey, self).__init__(value, Tags.KEY_MATERIAL)


class OpaqueKey(ByteString):

    def __init__(self, value=None):
        super(OpaqueKey, self).__init__(value, Tags.KEY_MATERIAL)


class PKCS1Key(ByteString):

    def __init__(self, value=None):
        super(PKCS1Key, self).__init__(value, Tags.KEY_MATERIAL)


class PKCS8Key(ByteString):

    def __init__(self, value=None):
        super(PKCS8Key, self).__init__(value, Tags.KEY_MATERIAL)


class X509Key(ByteString):

    def __init__(self, value=None):
        super(X509Key, self).__init__(value, Tags.KEY_MATERIAL)


class ECPrivateKey(ByteString):

    def __init__(self, value=None):
        super(ECPrivateKey, self).__init__(value, Tags.KEY_MATERIAL)


# 2.1.7.1
class TransparentSymmetricKey(Struct):

    class Key(ByteString):

        def __init__(self, value=None):
            super(TransparentSymmetricKey.Key, self).__init__(value, Tags.KEY)

    def __init__(self, key=None):
        super(TransparentSymmetricKey, self).__init__(Tags.KEY_MATERIAL)
        self.key = key
        self.validate()

    def read(self, istream):
        super(TransparentSymmetricKey, self).read(istream)
        tstream = BytearrayStream(istream.read(self.length))

        self.key = TransparentSymmetricKey.Key()
        self.key.read(tstream)

        self.is_oversized(tstream)
        self.validate()

    def write(self, ostream):
        tstream = BytearrayStream()

        self.key.write(tstream)

        # Write the length and value of the key wrapping data
        self.length = tstream.length()
        super(TransparentSymmetricKey, self).write(ostream)
        ostream.write(tstream.buffer)

    def validate(self):
        self.__validate()

    def __validate(self):
        # TODO (peter-hamilton) Finish implementation.
        pass
