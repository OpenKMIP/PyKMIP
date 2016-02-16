# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
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

from kmip.core import enums
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

import sqlalchemy.types as types


Base = declarative_base()


def attribute_append_factory(index_attribute):
    def attribute_append(list_container, list_attribute, initiator):
        index = getattr(list_container, index_attribute)
        list_attribute.index = index
        setattr(list_container, index_attribute, index + 1)
        return list_attribute
    return attribute_append


class UsageMaskType(types.TypeDecorator):
    """
    Converts a list of enums.CryptographicUsageMask Enums in an integer
    bitmask. This allows the database to only store an integer instead of a
    list of enumbs. This also does the reverse of converting an integer bit
    mask into a list enums.CryptographicUsageMask Enums.
    """

    impl = types.Integer

    def process_bind_param(self, value, dialect):
        """
        Returns the integer value of the usage mask bitmask. This value is
        stored in the database.

        Args:
            value(list<enums.CryptographicUsageMask>): list of enums in the
            usage mask
            dialect(string): SQL dialect
        """
        bitmask = 0x00
        for e in value:
            bitmask = bitmask | e.value
        return bitmask

    def process_result_value(self, value, dialect):
        """
        Returns a new list of enums.CryptographicUsageMask Enums. This converts
        the integer value into the list of enums.

        Args:
            value(int): The integer value stored in the database that is used
                to create the list of enums.CryptographicUsageMask Enums.
            dialect(string): SQL dialect
        """
        masks = list()
        if value:
            for e in enums.CryptographicUsageMask:
                if e.value & value:
                    masks.append(e)
        return masks


class EnumType(types.TypeDecorator):
    """
    Converts a Python enum to an integer before storing it in the database.
    This also does the reverse of converting an integer into an enum object.
    This allows enums to be stored in a database.
    """

    impl = types.Integer

    def __init__(self, cls):
        """
        Create a new EnumType. This new EnumType requires a class object in the
        constructor. The class is used to construct new instances of the Enum
        when the integer value is retrieved from the database.

        Args:
            cls(class): An Enum class used to create new instances from integer
                values.
        """
        super(EnumType, self).__init__()
        self._cls = cls

    def process_bind_param(self, value, dialect):
        """
        Returns the integer value of the Enum. This value is stored in the
        database.

        Args:
            value(Enum): An Enum instance whose integer value is to be stored.
            dialect(string): SQL dialect
        """
        return value.value

    def process_result_value(self, value, dialect):
        """
        Returns a new Enum representing the value stored in the database. The
        Enum class type of the returned object is that of the cls parameter in
        the __init__ call.

        Args:
            value(int): The integer value stored in the database that is used
                to create the Enum
            dialect(string): SQL dialect
        """
        return self._cls(value)


class ManagedObjectName(Base):

    __tablename__ = 'managed_object_names'
    id = Column('id', Integer, primary_key=True)
    mo_uid = Column('mo_uid', Integer, ForeignKey('managed_objects.uid'))
    name = Column('name', String)
    index = Column('name_index', Integer)
    name_type = Column('name_type', EnumType(enums.NameType))

    mo = relationship('ManagedObject', back_populates='_names')

    def __init__(self, name, index=0,
                 name_type=enums.NameType.UNINTERPRETED_TEXT_STRING):
        self.name = name
        self.index = index
        self.name_type = name_type

    def __repr__(self):
        return ("<ManagedObjectName(name='%s', index='%d', type='%s')>" %
                (self.name, self.index, self.name_type))

    def __eq__(self, other):
        if isinstance(other, ManagedObjectName):
            if self.name != other.name:
                return False
            elif self.index != other.index:
                return False
            elif self.name_type != other.name_type:
                return False
            else:
                return True
        else:
            return NotImplemented

    def __ne__(self, other):
        if isinstance(other, ManagedObjectName):
            return not (self == other)
        else:
            return NotImplemented
