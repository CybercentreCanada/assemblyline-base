"""
Assemblyline's built in Object Document Model tool.

The classes in this module can be composed to build database
independent data models in python. This gives us:
 - single source of truth for our data schemas
 - database independent serialization
 - type checking


"""

import json
import copy
import arrow
from datetime import datetime


class KeyMaskException(KeyError):
    pass


class _Field:
    def __init__(self, name=None, index=None, store=None, copyto=None, default=None, default_set=None):
        self.index = index
        self.store = store
        self.copyto = []
        if isinstance(copyto, str):
            self.copyto.append(copyto)
        elif copyto:
            self.copyto.extend(copyto)

        self.name = name
        self.getter_function = None
        self.setter_function = None

        self.default = default
        self.default_set = True if default is not None else default_set

    def __get__(self, obj, objtype=None):
        """Read the value of this field from the model instance (obj)."""
        if self.name in obj.odm_removed:
            raise KeyMaskException(self.name)
        if self.getter_function:
            return self.getter_function(obj, obj.odm_py_obj[self.name])
        return obj.odm_py_obj[self.name]

    def __set__(self, obj, value):
        """Set the value of this field, calling a setter method if available."""
        if self.name in obj.odm_removed:
            raise KeyMaskException(self.name)
        value = self.check(value)
        if self.setter_function:
            value = self.setter_function(obj, value)
        obj.odm_py_obj[self.name] = value

    def getter(self, method):
        """Decorator to create getter method for a field."""
        out = copy.deepcopy(self)
        out.getter_function = method
        return out

    def setter(self, method):
        """
        Let fields be used as a decorator to define a setter method.

        >>> expiry = Date()
        >>>
        >>> @expiry.setter
        >>> def expiry(self, assign, value):
        >>>     assert value
        >>>     assign(value)
        """
        out = copy.deepcopy(self)
        out.setter_function = method
        return out

    def apply_defaults(self, index, store):
        """Used by the model decorator to pass through default parameters."""
        if self.index is None:
            self.index = index
        if self.store is None:
            self.store = store

    def fields(self):
        """
        Return the subfields/modified field data.

        For simple fields this is an identity function.
        """
        return {'': self}


class _DeletedField:
    pass


class Date(_Field):
    """A field storing a datetime value."""

    def check(self, value):
        # Use the arrow library to transform ??? to a datetime
        return arrow.get(value).datetime


class Boolean(_Field):
    """A field storing a boolean value."""

    def check(self, value):
        return bool(value)


class Keyword(_Field):
    """
    A field storing a short string with a technical interpritation.

    Examples: file hashes, service names, document ids
    """

    def check(self, value):
        return str(value)


class Text(_Field):
    """A field storing human readable text data."""

    def check(self, value):
        return str(value)


class IndexText(_Field):
    """A special field with special processing rules to simplify searching."""

    def check(self, value):
        return str(value)


class Integer(_Field):
    """A field storing an integer value."""

    def check(self, value):
        return int(value)


class Float(_Field):
    """A field storing a floating point value."""

    def check(self, value):
        return float(value)


# class Classification(Keyword):
#     """A field storing access control classification."""
#
#     def __init__(self, expand=True, *args, **kwargs):
#         """
#         An expanded classification is one that controls the access to the document
#         which holds it. If a classification field is only meant to store classification
#         information and not enforce it, expand should be false.
#         """
#         super().__init__(*args, **kwargs)
#         self.expand = expand


class TypedList(list):

    def __init__(self, type, *items):
        super().__init__([type.check(el) for el in items])
        self.type = type

    def append(self, item):
        super().append(self.type.check(item))

    def extend(self, sequence):
        super().extend(self.type.check(item) for item in sequence)

    def insert(self, index, item):
        super().insert(index, self.type.check(item))

    def __iconcat__(self, sequence):
        super().__iconcat__(self.type.check(item) for item in sequence)

    def __setitem__(self, index, item):
        super().__setitem__(index, self.type.check(item))

    # __setslice__


class List(_Field):
    """A field storing a sequence of typed elements."""

    def __init__(self, child_type, **kwargs):
        super().__init__(**kwargs)
        self.child_type = child_type

    def check(self, value):
        return TypedList(self.child_type, *value)

    def apply_defaults(self, index, store):
        """Initialize the default settings for the child field."""
        # First apply the default to the list itself
        super().apply_defaults(index, store)
        # Then pass through the initialized values on the list to the child type
        self.child_type.apply_defaults(self.index, self.store)


class Compound(_Field):
    def __init__(self, field_type, **kwargs):
        super().__init__(**kwargs)
        self.child_type = field_type

    def check(self, value):
        return self.child_type(value)

    def fields(self):
        out = dict()
        for name, field_data in self.child_type.fields().items():
            field_data = copy.deepcopy(field_data)
            field_data.apply_defaults(self.index, self.store)
            out[name] = field_data
        return out


class Model:
    @classmethod
    def name(cls):
        return cls.__name__.lower()

    @classmethod
    def fields(cls):
        """
        Describe the elements of the model with a name -> field object mapping.

        For compound fields return the field object.
        """
        out = dict()
        for name, field_data in cls.__dict__.items():
            if isinstance(field_data, _Field):
                out[name] = field_data
        return out

    @classmethod
    def flat_fields(cls):
        """
        Describe the elements of the model with a name -> field object mapping.

        Recurse into compound fields, concatinating the names with '.' separators.
        """
        out = dict()
        for name, field_data in cls.__dict__.items():
            if isinstance(field_data, _Field):
                for sub_name, sub_data in field_data.fields().items():
                    out[(name + '.' + sub_name).strip('.')] = sub_data
        return out

    def __init__(self, data: dict, mask: list = None):
        if not isinstance(data, dict):
            raise TypeError("Models must be constructed with a dictionary")

        self.id = data.pop('_id', None)

        self.odm_py_obj = {}

        # Get the list of fields we expect this object to have
        fields = self.fields()
        self.odm_removed = {}
        if mask:
            self.odm_removed = {k: v for k, v in fields.items() if k not in mask}
            fields = {k: v for k, v in fields.items() if k in mask}

        # Trim out keys that actually belong to sub sections
        sub_data = {}
        for key, value in list(data.items()):
            if '.' in key:
                del data[key]
                child, sub_key = key.split('.', 1)
                try:
                    sub_data[child][sub_key] = value
                except KeyError:
                    sub_data[child] = {sub_key: value}
        data.update(sub_data)

        # Check to make sure we can use all the data we are given
        unused_keys = set(data.keys()) - set(fields.keys())
        if unused_keys:
            raise ValueError("{} created with unexpected parameters: {}".format(self.__class__.__name__, unused_keys))

        # Pass each value through it's respective validator, and store it
        for name, field_type in fields.items():
            try:
                value = data[name]
            except KeyError:
                if field_type.default_set:
                    value = field_type.default
                else:
                    raise ValueError('{} expected a parameter named {}'.format(self.__class__.__name__, name))

            self.odm_py_obj[name] = field_type.check(value)

    def _json(self):
        """Convert the object back into primatives that can be json serialized.

        TODO this is probably a major point that needs optimization.
        """
        def read(value):
            if isinstance(value, Model):
                return value._json()
            elif isinstance(value, datetime):
                return value.isoformat().replace('+00:00', 'Z')
            return value

        return {
            key: read(value)
            for key, value in self.odm_py_obj.items()
        }

    def json(self):
        return json.dumps(self._json())

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        for name, field in self.fields().items():
            if field.__get__(self) != field.__get__(other):
                return False

        return True


def model(index=None, store=None):
    """Decorator to create model objects."""
    def _finish_model(cls):
        for name, field_data in cls.fields().items():
            field_data.name = name
            field_data.apply_defaults(index=index, store=store)
        return cls
    return _finish_model
