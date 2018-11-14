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


def flat_to_nested(data: dict):
    sub_data = {}
    nested_keys = []
    for key, value in data.items():
        if '.' in key:
            child, sub_key = key.split('.', 1)
            nested_keys.append(child)
            try:
                sub_data[child][sub_key] = value
            except KeyError:
                sub_data[child] = {sub_key: value}
        else:
            sub_data[key] = value

    for key in nested_keys:
        sub_data[key] = flat_to_nested(sub_data[key])

    return sub_data


class KeyMaskException(KeyError):
    pass


class UndefinedFunction(Exception):
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
        >>> # noinspection PyUnusedLocal
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

    def check(self, value, **kwargs):
        raise UndefinedFunction("This function is not defined in the default field. "
                                "Each fields has to have their own definition")


class _DeletedField:
    pass


class Date(_Field):
    """A field storing a datetime value."""

    def check(self, value, **kwargs):
        # Use the arrow library to transform ??? to a datetime
        return arrow.get(value).datetime


class Boolean(_Field):
    """A field storing a boolean value."""

    def check(self, value, **kwargs):
        return bool(value)


class Keyword(_Field):
    """
    A field storing a short string with a technical interpritation.

    Examples: file hashes, service names, document ids
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.empty = ''

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                value = self.default
            else:
                raise ValueError("Empty strings are not allow without defaults")
        return str(value)


class Text(_Field):
    """A field storing human readable text data."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.empty = ''

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                value = self.default
            else:
                raise ValueError("Empty strings are not allow without defaults")

        return str(value)


class IndexText(_Field):
    """A special field with special processing rules to simplify searching."""

    def check(self, value, **kwargs):
        return str(value)


class Integer(_Field):
    """A field storing an integer value."""

    def check(self, value, **kwargs):
        return int(value)


class Float(_Field):
    """A field storing a floating point value."""

    def check(self, value, **kwargs):
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

    def __init__(self, type_p, *items):
        super().__init__([type_p.check(el) for el in items])
        self.type = type_p

    def append(self, item):
        super().append(self.type.check(item))

    def extend(self, sequence):
        super().extend(self.type.check(item) for item in sequence)

    def insert(self, index, item):
        super().insert(index, self.type.check(item))

    def __setitem__(self, index, item):
        if isinstance(index, slice):
            item = [self.type.check(val) for val in item]
            super().__setitem__(index, item)
        else:
            super().__setitem__(index, self.type.check(item))


class List(_Field):
    """A field storing a sequence of typed elements."""

    def __init__(self, child_type, **kwargs):
        super().__init__(**kwargs)
        self.child_type = child_type
        self.empty = []

    def check(self, value, **kwargs):
        return TypedList(self.child_type, *value)

    def apply_defaults(self, index, store):
        """Initialize the default settings for the child field."""
        # First apply the default to the list itself
        super().apply_defaults(index, store)
        # Then pass through the initialized values on the list to the child type
        self.child_type.apply_defaults(self.index, self.store)

    def fields(self):
        out = dict()
        for name, field_data in self.child_type.fields().items():
            field_data = copy.deepcopy(field_data)
            field_data.apply_defaults(self.index, self.store)
            out[name] = field_data
        return out


class Compound(_Field):
    def __init__(self, field_type, **kwargs):
        super().__init__(**kwargs)
        self.child_type = field_type

    def check(self, value, mask=None):
        return self.child_type(value, mask=mask)

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
        return cls.__name__

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

    def __init__(self, data: dict, mask: list = tuple(), docid=None):
        if not hasattr(data, 'items'):
            raise TypeError('Model must be constructed with dict like')
        self.odm_py_obj = {}
        self.id = docid

        # Parse the field mask for sub models
        mask_map = {}
        if mask:
            for entry in mask:
                if '.' in entry:
                    child, sub_key = entry.split('.', 1)
                    try:
                        mask_map[child].append(sub_key)
                    except KeyError:
                        mask_map[child] = [sub_key]
                else:
                    mask_map[entry] = None

        # Get the list of fields we expect this object to have
        fields = self.fields()
        self.odm_removed = {}
        if mask:
            self.odm_removed = {k: v for k, v in fields.items() if k not in mask_map}
            fields = {k: v for k, v in fields.items() if k in mask_map}

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
            params = {}
            if name in mask_map and mask_map[name]:
                params['mask'] = mask_map[name]

            try:
                value = data[name]
            except KeyError:
                if field_type.default_set:
                    value = copy.copy(field_type.default)
                else:
                    raise ValueError('{} expected a parameter named {}'.format(self.__class__.__name__, name))

            self.odm_py_obj[name] = field_type.check(value, **params)

    def as_primitives(self):
        """Convert the object back into primatives that can be json serialized.

        TODO this is probably a major point that needs optimization.
        """
        def read(value):
            if isinstance(value, Model):
                return value.as_primitives()
            elif isinstance(value, datetime):
                return value.isoformat().replace('+00:00', 'Z')
            return value

        fields = self.fields()

        return {
            key: read(value)
            for key, value in self.odm_py_obj.items() if value or (not value and fields[key].default_set)
        }

    def json(self):
        return json.dumps(self.as_primitives())

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        if len(self.odm_py_obj) != len(other.odm_py_obj):
            return False

        for name, field in self.fields().items():
            if name in self.odm_removed:
                continue
            if field.__get__(self) != field.__get__(other):
                return False

        return True

    def __repr__(self):
        if self.id:
            return f"<{self.name()} {self.id} {self.json()}>"
        return f"<{self.name()} {self.json()}>"


def model(index=None, store=None):
    """Decorator to create model objects."""
    def _finish_model(cls):
        for name, field_data in cls.fields().items():
            field_data.name = name
            field_data.apply_defaults(index=index, store=store)
        return cls
    return _finish_model
