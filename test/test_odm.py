from assemblyline.datastore.odm import model, Model
from assemblyline.datastore.odm import Compound, List, Keyword, Integer

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
    @model()
    class SubModel(Model):
        default = Keyword()
        indexed = Keyword(index=True)
        not_indexed = Keyword(index=False)

    @model()
    class Test1(Model):
        default = Compound(SubModel)
        indexed = Compound(SubModel, index=True)
        not_indexed = Compound(SubModel, index=False)

    fields = Test1.flat_fields()
    assert fields['default.default'].index is None
    assert fields['default.indexed'].index is True
    assert fields['default.not_indexed'].index is False

    fields = Test1.flat_fields()
    assert fields['indexed.default'].index is True
    assert fields['indexed.indexed'].index is True
    assert fields['indexed.not_indexed'].index is False

    fields = Test1.flat_fields()
    assert fields['not_indexed.default'].index is False
    assert fields['not_indexed.indexed'].index is True
    assert fields['not_indexed.not_indexed'].index is False


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


def test_getters():
    @model()
    class Test(Model):
        first = Integer()

        @first.getter
        def first(self, value):
            return value if value >= 1 else 100

    instance = Test(first=10)
    assert instance.first == 10

    instance.first = -1
    assert instance.first == 100

    instance.first = 500
    assert instance.first == 500


def test_create_compound():

    @model()
    class TestCompound(Model):
        key = Keyword()
        value = Keyword()

    @model()
    class Test(Model):
        first = Compound(TestCompound)

    test = Test(first={'key': 'a', 'value': 'b'})
    assert test.first.key == 'a'
    test.first.key = 100
    assert test.first.key == '100'


def test_create_list():
    @model()
    class Test(Model):
        values = List(Integer())

    test = Test(values=[])
    test = Test(values=[0, 100])

    with pytest.raises(ValueError):
        Test(values=['bugs'])

    with pytest.raises(ValueError):
        Test(values='bugs')

    assert test.values[0] == 0
    assert test.values[1] == 100

    test.values.append(10)
    assert len(test.values) == 3

    with pytest.raises(ValueError):
        test.values.append('cats')

    with pytest.raises(ValueError):
        test.values[0] = 'cats'


# def test_create_list_compounds():
