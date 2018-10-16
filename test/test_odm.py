from assemblyline.datastore.odm import model, Model
from assemblyline.datastore.odm import compound, Compound
from assemblyline.datastore.odm import Keyword, Integer

import pytest


class CatError(Exception):
    """A unique exception class."""
    pass


def test_index_defaults():
    @model()
    class Test1(Model):
        default = Keyword()
        indexed = Keyword(index=True)
        not_indexed = Keyword(index=False)

    fields = dict(Test1.fields())
    assert fields['default'].index is None
    assert fields['indexed'].index is True
    assert fields['not_indexed'].index is False

    @model(index=True)
    class Test2(Model):
        default = Keyword()
        indexed = Keyword(index=True)
        not_indexed = Keyword(index=False)

    fields = dict(Test2.fields())
    assert fields['default'].index is True
    assert fields['indexed'].index is True
    assert fields['not_indexed'].index is False

    @model(index=False)
    class Test3(Model):
        default = Keyword()
        indexed = Keyword(index=True)
        not_indexed = Keyword(index=False)

    fields = dict(Test3.fields())
    assert fields['default'].index is False
    assert fields['indexed'].index is True
    assert fields['not_indexed'].index is False


def test_compound_index_defaults():
    @compound
    class TestCompound(Compound):
        default = Keyword()
        indexed = Keyword(index=True)
        not_indexed = Keyword(index=False)

    @model()
    class Test1(Model):
        default = TestCompound()
        indexed = TestCompound(index=True)
        not_indexed = TestCompound(index=False)

    fields = dict(Test1.fields())['default'].children
    assert fields['default'].index is None
    assert fields['indexed'].index is True
    assert fields['not_indexed'].index is False

    fields = dict(Test1.fields())['indexed'].children
    assert fields['default'].index is True
    assert fields['indexed'].index is True
    assert fields['not_indexed'].index is False

    fields = dict(Test1.fields())['not_indexed'].children
    assert fields['default'].index is False
    assert fields['indexed'].index is True
    assert fields['not_indexed'].index is False


def test_creation():
    @model()
    class Test(Model):
        first = Keyword()
        second = Integer()

    instance = Test(first='abc', second=567)

    assert instance.first == 'abc'
    assert instance.second == 567

    instance.first = 'xyz'
    instance.second = 123

    assert instance.first == 'xyz'
    assert instance.second == 123


def test_type_validation():
    @model()
    class Test(Model):
        first = Keyword()
        second = Integer()

    with pytest.raises(ValueError):
        Test(cats=123)

    instance = Test(first='abc', second=567)

    with pytest.raises(ValueError):
        instance.second = 'cats'


def test_setters():
    @model()
    class Test(Model):
        first = Keyword()

        @first.setter
        def first(self, value):
            assert isinstance(value, str)
            if value.startswith('cat'):
                raise CatError()
            self._first = value

    instance = Test(first='abc')
    assert instance.first == 'abc'

    instance.first = 'xyz'
    assert instance.first == 'xyz'

    instance.first = 123
    assert instance.first == '123'

    with pytest.raises(CatError):
        instance.first = 'cats'

# 
# def test_create_compound():
#
#     @model()
#     class Test(Model):
#         first = Keyword()
#
#         @first.setter
#         def first(self, value):
#             assert isinstance(value, str)
#             if value.startswith('cat'):
#                 raise CatError()
#             self._first = value
#
#     raise NotImplementedError()
#
#
# def test_create_list():
#     raise NotImplementedError()
