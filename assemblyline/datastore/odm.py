"""
Assemblyline's built in Object Document Model tool.

The classes in this module can be composed to build database
independent data models in python. This gives us:
 - single source of truth for our data schemas
 - database independent serialization
 - type checking


"""

import copy
from datetime import datetime


class _Field:
    def __init__(self, index=None, store=None, copyto=None, name=None):
        """
        Abstract base for a field in a model.

        This base field has no type; the typed children of this class should be used.

        Args:
            index (bool): Index this field for fast searching.
            store (bool): Store the field value in the index for fast reading.
            copyto (str): Add the values of this field under another name.
            name (str): The name of this field. (Set by the model decorator usually)
        """
        self.index = index
        self.store = store
        self.copyto = []
        if isinstance(copyto, str):
            self.copyto.append(copyto)
        elif copyto:
            self.copyto.extend(copyto)

        self.name = name
        self.setter_function = None

    def __get__(self, obj, objtype=None):
        """Read the value of this field from the model instance (obj)."""
        return getattr(obj, '_' + self.name)

    def __set__(self, obj, value):
        """Set the value of this field, calling a setter method if available."""
        value = self.check(value)
        if self.setter_function:
            return self.setter_function(obj, value)
        setattr(obj, '_' + self.name, value)

    def setter(self, method):
        """
        Let fields be used as a decorator to define a setter method.

        >>> expiry = Date()
        >>>
        >>> @expiry.setter
        >>> def expiry(self, value):
        >>>     assert value
        >>>     self._expiry = value
        """
        self.setter_function = method
        return self

    def apply_defaults(self, index, store):
        """Used by the model decorator to pass through default parameters."""
        if self.index is None:
            self.index = index
        if self.store is None:
            self.store = store


class Date(_Field):
    """A field storing a datetime value."""

    def check(self, value):
        if isinstance(value, datetime):
            return value
        raise ValueError('Failed to interpret value as a date')


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


class Classification(Keyword):
    """A field storing access control classification."""

    def __init__(self, expand=True, *args, **kwargs):
        """
        An expanded classification is one that controls the access to the document
        which holds it. If a classification field is only meant to store classification
        information and not enforce it, expand should be false.
        """
        super().__init__(*args, **kwargs)
        self.expand = expand


class List(_Field):
    """A field storing a sequence of typed elements."""

    def __init__(self, child_type, **kwargs):
        super().__init__(**kwargs)
        self.child_type = child_type

    def check(self, value):
        return [self.child_type.check(el) for el in value]

    def apply_defaults(self, index, store):
        """Initialize the default settings for the child field."""
        # First apply the default to the list itself
        super().apply_defaults(index, store)
        # Then pass through the initialized values on the list to the child type
        self.child_type.apply_defaults(self.index, self.store)


class Compound(_Field):
    """
    A field composed from several other fields.

    A compound field should inherit from this class, and have the class decorator
    `compound` applied to it.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.children = {}
        for name, field_data in self.__class__.__dict__.items():
            if not isinstance(field_data, _Field):
                continue
            self.children[name] = copy.deepcopy(field_data)

    def fields(self):
        """Describe the elements of the compound field with a name -> field object mapping."""
        return self.children

    def apply_defaults(self, index, store):
        """Initialize the default settings for all components of the compound field."""
        super().apply_defaults(index, store)
        for type in self.children.values():
            type.apply_defaults(self.index, self.store)


def compound(cls):
    """Decorator to create compound model fields."""
    for name, field_data in cls.__dict__.items():
        if not isinstance(field_data, _Field):
            continue
        field_data.name = name
    return cls


class Model:
    @classmethod
    def name(cls):
        return cls.__name__.lower()

    @classmethod
    def fields(cls):
        """Describe the elements of the model with a name -> field object mapping."""
        out = dict()
        for name, field_data in cls.__dict__.items():
            if not isinstance(field_data, _Field):
                continue
            out[name] = field_data
        return out

    def __init__(self, **data):
        fields = self.fields()

        # Check to make sure we can use all the data we are given
        unused_keys = set(data.keys()) - set(fields.keys())
        if unused_keys:
            raise ValueError("{} created with unexpected parameters: {}".format(self.__class__.__name__, unused_keys))

        # Pass each value through it's respective validator, and store it
        for name, field_type in fields.items():
            if name not in data:
                raise ValueError('{} expected a parameter named {}'.format(self.__class__.__name__, name))
            value = field_type.check(data[name])
            setattr(self, '_' + name, value)


def model(index=None, store=None):
    """Decorator to create model objects."""
    def _finish_model(cls):
        for name, field_data in cls.fields().items():
            field_data.name = name
            field_data.apply_defaults(index=index, store=store)
        return cls
    return _finish_model
