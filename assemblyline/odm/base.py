"""
Assemblyline's built in Object Document Model tool.

The classes in this module can be composed to build database
independent data models in python. This gives us:
- single source of truth for our data schemas
- database independent serialization
- type checking


"""

import copy
import json
import re
import typing
from datetime import datetime

import arrow
from dateutil.tz import tzutc

from assemblyline.common import forge
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.uid import get_random_id

BANNED_FIELDS = {"id", "__access_grp1__", "__access_lvl__", "__access_req__", "__access_grp2__"}
DATEFORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
FIELD_SANITIZER = re.compile("^[a-z][a-z0-9_]*$")
UTC_TZ = tzutc()

DOMAIN_REGEX = r"(?:(?:[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff_-]{0,62})?[a-z0-9\u00a1-\uffff]\.)+(?:[a-z\u00a1-\uffff]{2,}\.?)"
DOMAIN_ONLY_REGEX = f"^{DOMAIN_REGEX}$"
IP_REGEX = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
IP_ONLY_REGEX = f"^{IP_REGEX}$"
PHONE_REGEX = r"^(\+?\d{1,2})?[ .-]?(\(\d{3}\)|\d{3})[ .-](\d{3})[ .-](\d{4})$"
SSDEEP_REGEX = r"^[0-9]{1,18}:[a-zA-Z0-9]{1,64}:[a-zA-Z0-9]{1,64}$"
MD5_REGEX = r"^[a-f0-9]{32}$"
SHA1_REGEX = r"^[a-f0-9]{40}$"
SHA256_REGEX = r"^[a-f0-9]{64}$"
MAC_REGEX = r"^(?:(?:[0-9a-f]{2}-){5}[0-9a-f]{2}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2})$"
URI_PATH = r"(?:[/?#]\S*)"
FULL_URI = f"^(?:(?:(?:https?|ftp):)?//)(?:\\S+(?::\\S*)?@)?(?:{IP_REGEX}|{DOMAIN_REGEX})(?::\\d{{2,5}})?{URI_PATH}?$"


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
    def __init__(self, name=None, index=None, store=None, copyto=None, default=None):
        self.index = index
        self.store = store
        self.multivalued = False
        self.copyto = []
        if isinstance(copyto, str):
            self.copyto.append(copyto)
        elif copyto:
            self.copyto.extend(copyto)

        self.name = name
        self.getter_function = None
        self.setter_function = None

        self.default = default
        self.default_set = default is not None

    # noinspection PyProtectedMember
    def __get__(self, obj, objtype=None):
        """Read the value of this field from the model instance (obj)."""
        if obj is None:
            return obj
        if self.name in obj._odm_removed:
            raise KeyMaskException(self.name)
        if self.getter_function:
            return self.getter_function(obj, obj._odm_py_obj[self.name])
        return obj._odm_py_obj[self.name]

    # noinspection PyProtectedMember
    def __set__(self, obj, value):
        """Set the value of this field, calling a setter method if available."""
        if self.name in obj._odm_removed:
            raise KeyMaskException(self.name)
        value = self.check(value)
        if self.setter_function:
            value = self.setter_function(obj, value)
        obj._odm_py_obj[self.name] = value

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
        >>> # noinspection PyUnusedLocal,PyUnresolvedReferences
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


class Any(_Field):
    def __init__(self, *args, **kwargs):
        kwargs['index'] = False
        kwargs['store'] = False
        super().__init__(*args, **kwargs)

    def check(self, value, **kwargs):
        return value


class Date(_Field):
    """A field storing a datetime value."""

    def check(self, value, **kwargs):
        if value is None:
            return None

        if value == "NOW":
            value = now_as_iso()

        try:
            return datetime.strptime(value, DATEFORMAT).replace(tzinfo=UTC_TZ)
        except (TypeError, ValueError):
            return arrow.get(value).datetime


class Boolean(_Field):
    """A field storing a boolean value."""

    def check(self, value, **kwargs):
        return bool(value)


class Keyword(_Field):
    """
    A field storing a short string with a technical interpretation.

    Examples: file hashes, service names, document ids
    """

    def check(self, value, **kwargs):
        # We have a special case for bytes here due to how often strings and bytes
        # get mixed up in python apis
        if isinstance(value, bytes):
            raise ValueError(f"Keyword ({self.name}) doesn't accept bytes values")

        if value == '' or value is None:
            if self.default_set:
                value = self.default
            else:
                raise ValueError(f"Empty strings are not allow without defaults for field '{self.name}'")

        if value is None:
            return None

        return str(value)


class ValidatedKeyword(Keyword):
    """
    Keyword field which the values are validated by a regular expression
    """
    def __init__(self, validation_regex, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.validation_regex = re.compile(validation_regex)

    def __deepcopy__(self, memo=None):
        # NOTE: This deepcopy code does not work with a sub-class that add args of kwargs that should be copied.
        #       If that is the case, the sub-class should implement its own deepcopy function.
        valid_fields = ["name", "index", "store", "copyto", "default"]
        if 'validation_regex' in self.__class__.__init__.__code__.co_varnames:
            return self.__class__(self.validation_regex.pattern, **{k: v for k, v in self.__dict__.items()
                                                                      if k in valid_fields})
        else:
            return self.__class__(**{k: v for k, v in self.__dict__.items() if k in valid_fields})

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                value = self.default
            else:
                raise ValueError(f"Empty strings are not allow without defaults (field: {self.name})")

        if value is None:
            return value

        if not self.validation_regex.match(value):
            raise ValueError(f"'{value}' not match the validator: {self.validation_regex.pattern}")

        return str(value)


class IP(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(IP_ONLY_REGEX, *args, **kwargs)


class Domain(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(DOMAIN_ONLY_REGEX, *args, **kwargs)


class URI(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(FULL_URI, *args, **kwargs)


class URIPath(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(URI_PATH, *args, **kwargs)


class MAC(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(MAC_REGEX, *args, **kwargs)


class PhoneNumber(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(PHONE_REGEX, *args, **kwargs)


class SSDeepHash(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(SSDEEP_REGEX, *args, **kwargs)


class SHA1(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(SHA1_REGEX, *args, **kwargs)


class SHA256(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(SHA256_REGEX, *args, **kwargs)


class MD5(ValidatedKeyword):
    def __init__(self, *args, **kwargs):
        super().__init__(MD5_REGEX, *args, **kwargs)


class Enum(Keyword):
    """
    A field storing a short string that has predefined list of possible values
    """
    def __init__(self, values, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.values = set(values)

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                value = self.default
            else:
                raise ValueError("Empty enums are not allow without defaults")

        if value not in self.values:
            raise ValueError(f"{value} not in the possible values: {self.values}")

        if value is None:
            return value

        return str(value)


class UUID(Keyword):
    """
    A field storing an auto-generated unique ID if None is provided
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_set = True

    def check(self, value, **kwargs):
        if value is None:
            value = get_random_id()
        return str(value)


class Text(_Field):
    """A field storing human readable text data."""

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                value = self.default
            else:
                raise ValueError("Empty strings are not allow without defaults")

        if value is None:
            return None

        return str(value)


class IndexText(_Field):
    """A special field with special processing rules to simplify searching."""

    def check(self, value, **kwargs):
        return str(value)


class Integer(_Field):
    """A field storing an integer value."""

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                return self.default
        return int(value)


class Float(_Field):
    """A field storing a floating point value."""

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                return self.default
        return float(value)


class ClassificationObject(object):
    def __init__(self, engine, value, is_uc=False):
        self.engine = engine
        self.is_uc = is_uc
        self.value = engine.normalize_classification(value, skip_auto_select=is_uc)

    def get_access_control_parts(self):
        return self.engine.get_access_control_parts(self.value, user_classification=self.is_uc)

    def min(self, other):
        return ClassificationObject(self.engine,
                                    self.engine.min_classification(self.value, other.value),
                                    is_uc=self.is_uc)

    def max(self, other):
        return ClassificationObject(self.engine,
                                    self.engine.max_classification(self.value, other.value),
                                    is_uc=self.is_uc)

    def intersect(self, other):
        return ClassificationObject(self.engine,
                                    self.engine.intersect_user_classification(self.value, other.value),
                                    is_uc=self.is_uc)

    def long(self):
        return self.engine.normalize_classification(self.value, skip_auto_select=self.is_uc)

    def small(self):
        return self.engine.normalize_classification(self.value, long_format=False, skip_auto_select=self.is_uc)

    def __str__(self):
        return self.value

    def __eq__(self, other):
        return self.value == other.value

    def __ne__(self, other):
        return self.value != other.value

    def __le__(self, other):
        return self.engine.is_accessible(other.value, self.value)

    def __lt__(self, other):
        return self.engine.is_accessible(other.value, self.value)

    def __ge__(self, other):
        return self.engine.is_accessible(self.value, other.value)

    def __gt__(self, other):
        return not self.engine.is_accessible(other.value, self.value)


class Classification(Keyword):
    """A field storing access control classification."""

    def __init__(self, *args, is_user_classification=False, yml_config=None, **kwargs):
        """
        An expanded classification is one that controls the access to the document
        which holds it.
        """
        super().__init__(*args, **kwargs)
        self.engine = forge.get_classification(yml_config=yml_config)
        self.is_uc = is_user_classification

    def check(self, value, **kwargs):
        if isinstance(value, ClassificationObject):
            return ClassificationObject(self.engine, value.value, is_uc=self.is_uc)
        return ClassificationObject(self.engine, value, is_uc=self.is_uc)


class ClassificationString(Keyword):
    """A field storing the classification as a string only."""

    def __init__(self, *args, yml_config=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.engine = forge.get_classification(yml_config=yml_config)

    def check(self, value, **kwargs):
        if not value:
            if self.default_set:
                value = self.default
            else:
                raise ValueError("Empty classification is not allowed without defaults")

        if not self.engine.is_valid(value):
            raise ValueError(f"Invalid classification: {value}")

        return str(value)


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

    def check(self, value, **kwargs):
        if isinstance(self.child_type, Compound) and isinstance(value, dict):
            # Search queries of list of compound fields will return dotted paths of list of
            # values. When processed through the flat_fields function, since this function
            # has no idea about the data layout, it will transform the dotted paths into
            # a dictionary of items then contains a list of object instead of a list
            # of dictionaries with single items.

            # The following piece of code transforms the dictionary of list into a list of
            # dictionaries so the rest of the model validation can go through.
            return TypedList(self.child_type, *[dict(zip(value, t)) for t in zip(*value.values())])

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


class TypedMapping(dict):
    def __init__(self, type_p, index, store, **items):
        self.index = index
        self.store = store
        if self.index or self.store:
            self.sanitizer = FIELD_SANITIZER
        else:
            self.sanitizer = re.compile("^[A-Za-z0-9_ ]*$")
        for key in items.keys():
            if not self.sanitizer.match(key):
                raise KeyError(f"Illegal key: {key}")
        super().__init__({key: type_p.check(el) for key, el in items.items()})
        self.type = type_p

    def __setitem__(self, key, item):
        if not self.sanitizer.match(key):
            raise KeyError(f"Illegal key: {key}")
        return super().__setitem__(key, self.type.check(item))

    def update(self, *args, **kwargs):
        # Update supports three input layouts:
        # 1. A single dictionary
        if len(args) == 1 and isinstance(args[0], dict):
            for key in args[0].keys():
                if not self.sanitizer.match(key):
                    raise KeyError(f"Illegal key: {key}")
            return super().update({key: self.type.check(item) for key, item in args[0].items()})

        # 2. A list of key value pairs as if you were constructing a dictionary
        elif args:
            for key, value in args:
                if not self.sanitizer.match(key):
                    raise KeyError(f"Illegal key: {key}")
            return super().update({key: self.type.check(item) for key, item in args})

        # 3. Key values as arguments, can be combined with others
        if kwargs:
            for key in kwargs.keys():
                if not self.sanitizer.match(key):
                    raise KeyError(f"Illegal key: {key}")
            return super().update({key: self.type.check(item) for key, item in kwargs.items()})


class Mapping(_Field):
    """A field storing a sequence of typed elements."""

    def __init__(self, child_type, **kwargs):
        super().__init__(**kwargs)
        self.child_type = child_type

    def check(self, value, **kwargs):
        return TypedMapping(self.child_type, self.index, self.store, **value)

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

    def check(self, value, mask=None):
        if isinstance(value, self.child_type):
            return value
        return self.child_type(value, mask=mask)

    def fields(self):
        out = dict()
        for name, field_data in self.child_type.fields().items():
            field_data = copy.deepcopy(field_data)
            field_data.apply_defaults(self.index, self.store)
            out[name] = field_data
        return out


class Optional(_Field):
    """A wrapper field to allow simple types (int, float, bool) to take None values."""
    def __init__(self, child_type, **kwargs):
        if child_type.default_set:
            kwargs['default'] = child_type.default
        super().__init__(**kwargs)
        self.default_set = True
        self.child_type = child_type

    def check(self, value, *args, **kwargs):
        if value is None:
            return None
        return self.child_type.check(value, *args, **kwargs)

    def fields(self):
        return self.child_type.fields()

    def apply_defaults(self, index, store):
        super().apply_defaults(index, store)
        self.child_type.apply_defaults(self.index, self.store)


class Model:
    @classmethod
    def name(cls):
        return cls.__name__

    @classmethod
    def fields(cls, skip_mappings=False) -> typing.Mapping[str, _Field]:
        """
        Describe the elements of the model.

        For compound fields return the field object.

        Args:
            skip_mappings (bool): Skip over mappings where the real subfield names are unknown.
        """
        if skip_mappings and hasattr(cls, '_odm_field_cache_skip'):
            return cls._odm_field_cache_skip

        if not skip_mappings and hasattr(cls, '_odm_field_cache'):
            return cls._odm_field_cache

        out = dict()
        for name, field_data in cls.__dict__.items():
            if isinstance(field_data, _Field):
                if skip_mappings and isinstance(field_data, Mapping):
                    continue
                out[name] = field_data

        if skip_mappings:
            cls._odm_field_cache_skip = out
        else:
            cls._odm_field_cache = out
        return out

    @staticmethod
    def _recurse_fields(name, field, skip_mappings, multivalued=False):
        out = dict()
        for sub_name, sub_field in field.fields().items():
            sub_field.multivalued = multivalued

            if skip_mappings and isinstance(sub_field, Mapping):
                continue

            elif isinstance(sub_field, Any):
                continue

            elif isinstance(sub_field, (List, Optional, Compound)) and sub_name != "":
                out.update(Model._recurse_fields(".".join([name, sub_name]), sub_field.child_type, skip_mappings,
                                                 multivalued=multivalued or isinstance(sub_field, List)))

            elif sub_name:
                out[".".join([name, sub_name])] = sub_field

            else:
                out[name] = sub_field
        return out

    @classmethod
    def flat_fields(cls, skip_mappings=False) -> typing.Mapping[str, _Field]:
        """
        Describe the elements of the model.

        Recurse into compound fields, concatenating the names with '.' separators.

        Args:
            skip_mappings (bool): Skip over mappings where the real subfield names are unknown.
        """
        out = dict()
        for name, field in cls.__dict__.items():
            if isinstance(field, _Field):
                if skip_mappings and isinstance(field, Mapping):
                    continue
                if isinstance(field, Any):
                    continue
                out.update(Model._recurse_fields(name, field, skip_mappings, multivalued=isinstance(field, List)))
        return out

    # Allow attribute assignment by default in the constructor until it is removed
    __frozen = False

    def __init__(self, data: dict = None, mask: list = None, docid=None):
        if data is None:
            data = {}
        if not hasattr(data, 'items'):
            raise TypeError(f"'{self.__class__.__name__}' object must be constructed with dict like")
        self._odm_py_obj = {}
        self.id = docid

        # Parse the field mask for sub models
        mask_map = {}
        if mask is not None:
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
        self._odm_removed = {}
        if mask is not None:
            self._odm_removed = {k: v for k, v in fields.items() if k not in mask_map}
            fields = {k: v for k, v in fields.items() if k in mask_map}

        # Trim out keys that actually belong to sub sections
        data = flat_to_nested(data)

        # Check to make sure we can use all the data we are given
        unused_keys = set(data.keys()) - set(fields.keys()) - BANNED_FIELDS
        if unused_keys:
            raise ValueError(f"'{self.__class__.__name__}' object was created with invalid parameters: "
                             f"{', '.join(unused_keys)}")

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
                    raise ValueError(f"Object '{self.__class__.__name__}' expected a parameter named: {name}")

            self._odm_py_obj[name] = field_type.check(value, **params)

        # Since the layout of model objects should be fixed, don't allow any further
        # attribute assignment
        self.__frozen = True

    def as_primitives(self, hidden_fields=False, strip_null=False):
        """Convert the object back into primitives that can be json serialized."""
        out = {}

        fields = self.fields()
        for key, value in self._odm_py_obj.items():
            field_type = fields[key]
            if value is not None or (value is None and field_type.default_set):
                if strip_null and value is None:
                    continue

                if isinstance(value, Model):
                    out[key] = value.as_primitives(strip_null=strip_null)
                elif isinstance(value, datetime):
                    out[key] = value.strftime(DATEFORMAT)
                elif isinstance(value, TypedMapping):
                    out[key] = {k: v.as_primitives(strip_null=strip_null)
                                if isinstance(v, Model) else v for k, v in value.items()}
                elif isinstance(value, (List, TypedList)):
                    out[key] = [v.as_primitives(strip_null=strip_null)
                                if isinstance(v, Model) else v for v in value]
                elif isinstance(value, ClassificationObject):
                    out[key] = str(value)
                    if hidden_fields:
                        out.update(value.get_access_control_parts())
                else:
                    out[key] = value
        return out

    def json(self):
        return json.dumps(self.as_primitives())

    def __eq__(self, other):
        if isinstance(other, dict):
            try:
                other = self.__class__(other)
            except (ValueError, KeyError):
                return False

        elif not isinstance(other, self.__class__):
            return False

        if len(self._odm_py_obj) != len(other._odm_py_obj):
            return False

        for name, field in self.fields().items():
            if name in self._odm_removed:
                continue
            if field.__get__(self) != field.__get__(other):
                return False

        return True

    def __repr__(self):
        if self.id:
            return f"<{self.__class__.__name__} [{self.id}] {self.json()}>"
        return f"<{self.__class__.__name__} {self.json()}>"

    def __getitem__(self, name):
        return self._odm_py_obj[name]

    def __setitem__(self, name, value):
        if name not in self._odm_field_cache:
            raise KeyError(name)
        return self.__setattr__(name, value)

    def __getattr__(self, name):
        # Any attribute that hasn't been explicitly declared is forbidden
        raise KeyError(name)

    def __setattr__(self, name, value):
        # Any attribute that hasn't been explicitly declared is forbidden
        if self.__frozen and name not in self.fields():
            raise KeyError(name)
        return object.__setattr__(self, name, value)


def model(index=None, store=None):
    """Decorator to create model objects."""
    def _finish_model(cls):
        for name, field_data in cls.fields().items():
            if not FIELD_SANITIZER.match(name) or name in BANNED_FIELDS:
                raise ValueError(f"Illegal variable name: {name}")

            field_data.name = name

            if isinstance(field_data, Optional):
                field_data.child_type.name = name

            field_data.apply_defaults(index=index, store=store)
        return cls
    return _finish_model
