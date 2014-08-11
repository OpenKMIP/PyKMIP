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


class ErrorStrings:
    BAD_EXP_RECV = "Bad {0} {1}: expected {2}, received {3}"
    BAD_ENCODING = "Bad {0} {1}: encoding mismatch"


class BaseError(Exception):
    """Base class for exceptions defined in this module."""

    def __init__(self, args):
        [setattr(self, k, v) for k, v in args.iteritems() if k is not 'self']


class KMIPServerError(BaseError):
    """Base Exception for KMIP server errors."""
    def __init__(self, args):
        super(KMIPServerError, self).__init__(args)


class KMIPServerZombieError(KMIPServerError):
    """KMIP server error for hung and persistent live KMIP servers."""
    def __init__(self, pid):
        message = 'KMIP server alive after termination: PID {0}'.format(pid)
        super(KMIPServerZombieError, self).__init__({'message': message})

    def __str__(self):
        return self.message


class KMIPServerSuicideError(KMIPServerError):
    """KMIP server error for prematurely dead KMIP servers."""
    def __init__(self, pid):
        message = 'KMIP server dead prematurely: PID {0}'.format(pid)
        super(KMIPServerSuicideError, self).__init__({'message': message})

    def __str__(self):
        return self.message


class InitError(BaseError):
    """Exception thrown for bad initializations."""
    def __init__(self, cls, exp, recv):
        super(InitError, self).__init__(locals())

    def __str__(self):
        msg = "Tried to initialize {0} instance with bad type: "
        msg += "expected {1}, received {2}"
        return msg.format(self.cls, self.exp, self.recv)


class WriteValueError(BaseError):
    def __init__(self, cls, attr, value):
        super(WriteValueError, self).__init__(locals())

    def __str__(self):
        msg = "Tried to write {0}.{1} with invalid value: {2}"
        return msg.format(self.cls, self.attr, self.value)


class WriteTypeError(BaseError):
    def __init__(self, cls, attr, value):
        super(WriteTypeError, self).__init__(locals())

    def __str__(self):
        msg = "Tried to write {0}.{1} with invalid type: {2}"
        return msg.format(self.cls, self.attr, self.value)


class WriteOverflowError(BaseError):
    def __init__(self, cls, attr, exp, recv):
        super(WriteOverflowError, self).__init__(locals())

    def __str__(self):
        msg = "Tried to write {0}.{1} with too many bytes: "
        msg += "expected {2}, received {3}"
        return msg.format(self.cls, self.attr, self.exp, self.recv)


class ReadValueError(BaseError):
    def __init__(self, cls, attr, exp, recv):
        super(ReadValueError, self).__init__(locals())

    def __str__(self):
        msg = "Tried to read {0}.{1}: expected {2}, received {3}"
        return msg.format(self.cls, self.attr, self.exp, self.recv)


class InvalidLengthError(ValueError):
    def __init__(self, cls, exp, recv):
        msg = "Invalid length read for {0}: expected {1}, received {2}"
        super(InvalidLengthError, self).__init__(msg.format(cls, exp, recv))


class StreamNotEmptyError(BaseError):
    def __init__(self, cls, extra):
        super(StreamNotEmptyError, self).__init__(locals())

    def __str__(self):
        msg = "Invalid length used to read {0}, bytes remaining: {1}"
        return msg.format(self.cls, self.extra)


class StateTypeError(TypeError):
    def __init__(self, cls, exp, recv):
        msg = "Tried to initialize {0} instance with bad type: "
        msg += "expected {1}, received {2}"
        super(StateTypeError, self).__init__(msg.format(cls, exp, recv))


class StateOverflowError(ValueError):
    def __init__(self, cls, attr, exp, recv):
        msg = "Tried to write {0}.{1} with too many bytes: "
        msg += "expected {2}, received {3}"
        super(StateOverflowError, self).__init__(msg.format(cls, attr, exp,
                                                            recv))
