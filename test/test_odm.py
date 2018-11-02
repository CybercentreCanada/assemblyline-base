from assemblyline.datastore.odm import model, Model, KeyMaskException
from assemblyline.datastore.odm import Compound, List, Keyword, Integer

import json
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

    instance = Test(dict(first='abc', second=567))

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
        Test(dict(cats=123))

    instance = Test(dict(first='abc', second=567))

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
            return value

    instance = Test(dict(first='abc'))
    assert instance.first == 'abc'

    instance.first = 'xyz'
    assert instance.first == 'xyz'

    instance.first = 123
    assert instance.first == '123'

    with pytest.raises(CatError):
        instance.first = 'cats'


def test_setters_side_effects():
    """Test setters that change other field values."""
    @model()
    class Test(Model):
        a = Integer()
        b = Integer()
        best = Integer()

        @a.setter
        def a(self, value):
            self.best = min(self.b, value)
            return value

        @b.setter
        def b(self, value):
            self.best = min(self.a, value)
            return value

    instance = Test(dict(a=-100, b=10, best=-100))

    instance.a = 50
    assert instance.best == 10
    instance.b = -10
    assert instance.best == -10


def test_getters():
    @model()
    class Test(Model):
        first = Integer()

        @first.getter
        def first(self, value):
            return value if value >= 1 else 100

    instance = Test(dict(first=10))
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

    test = Test({'first': {'key': 'a', 'value': 'b'}})
    assert test.first.key == 'a'
    test.first.key = 100
    assert test.first.key == '100'


def test_json():

    @model()
    class Inner(Model):
        number = Integer()
        value = Keyword()

    @model()
    class Test(Model):
        a = Compound(Inner)
        b = Integer()

    a = Test(dict(b=10, a={'number': 499, 'value': 'cats'}))
    b = Test(json.loads(a.json()))

    assert b.b == 10
    assert b.a.number == 499
    assert b.a.value == 'cats'


def test_create_list():
    @model()
    class Test(Model):
        values = List(Integer())

    test = Test(dict(values=[]))
    test = Test(dict(values=[0, 100]))

    with pytest.raises(ValueError):
        Test(dict(values=['bugs']))

    with pytest.raises(ValueError):
        Test(dict(values='bugs'))

    assert test.values[0] == 0
    assert test.values[1] == 100

    test.values.append(10)
    assert len(test.values) == 3

    with pytest.raises(ValueError):
        test.values.append('cats')

    with pytest.raises(ValueError):
        test.values[0] = 'cats'


def test_create_list_compounds():
    @model()
    class Entry(Model):
        value = Integer()
        key = Keyword()

    @model()
    class Test(Model):
        values = List(Compound(Entry))

    test = Test(dict(values=[]))
    test = Test({'values': [
        {'key': 'cat', 'value': 0},
        {'key': 'rat', 'value': 100}
    ]})

    with pytest.raises(TypeError):
        Test(values=['bugs'])

    with pytest.raises(TypeError):
        Test(values='bugs')

    assert test.values[0].value == 0
    assert test.values[1].value == 100

    test.values.append({'key': 'bat', 'value': 50})

    assert len(test.values) == 3

    with pytest.raises(TypeError):
        test.values.append(1000)

    with pytest.raises(TypeError):
        test.values[0] = 'cats'

    with pytest.raises(ValueError):
        test.values[0] = {'key': 'bat', 'value': 50, 'extra': 1000}

    test.values[0].key = 'dog'


def test_defaults():

    @model()
    class InnerA(Model):
        number = Integer(default=10)
        value = Keyword()

    @model()
    class InnerB(Model):
        number = Integer()
        value = Keyword()

    @model()
    class Test(Model):
        a = Compound(InnerA)
        b = Compound(InnerB)
        c = Compound(InnerB, default={'number': 99, 'value': 'yellow'})
        x = Integer()
        y = Integer(default=-1)

    # Build a model with missing data found in the defaults
    test = Test({
        'a': {'value': 'red'},
        'b': {'number': -100, 'value': 'blue'},
        'x': -55
    })

    assert test.a.number == 10
    assert test.a.value == 'red'
    assert test.b.number == -100
    assert test.b.value == 'blue'
    assert test.c.number == 99
    assert test.c.value == 'yellow'
    assert test.x == -55
    assert test.y == -1


def test_field_masking():
    @model()
    class Test(Model):
        a = Integer()
        b = Integer()

    test = Test(dict(a=10), mask=['a'])

    assert test.a == 10

    with pytest.raises(KeyMaskException):
        test.b

    with pytest.raises(KeyMaskException):
        test.b = 100
