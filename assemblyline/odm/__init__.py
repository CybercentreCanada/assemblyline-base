from __future__ import annotations
import typing

from assemblyline.odm.base import *

# Imports that have the same effect as some part of the one above so that
# type checking can use this file properly.
from assemblyline.odm.base import Keyword, Optional, Boolean, Integer, List, Compound, Mapping, Date, Enum
from datetime import datetime

_InnerType = typing.TypeVar("_InnerType")

"""
Helper functions to invoke ODM types without requiring type annotations.

These can be used like the type objects they wrap, but will provide better hints to type checking tools.
"""


def description(text):
    def _fn(obj):
        obj.description = text
    return _fn


def keyword(*args, **kwargs) -> str:
    return typing.cast(str, Keyword(*args, **kwargs))


def date(*args, **kwargs) -> datetime:
    return typing.cast(datetime, Date(*args, **kwargs))


def optional(child_type: _InnerType, **kwargs) -> typing.Optional[_InnerType]:
    return typing.cast(typing.Optional[_InnerType], Optional(child_type, **kwargs))


def boolean(*args, **kwargs) -> bool:
    return typing.cast(bool, Boolean(*args, **kwargs))


def integer(*args, **kwargs) -> int:
    return typing.cast(int, Integer(*args, **kwargs))


def sequence(child_type: _InnerType, **kwargs) -> list[_InnerType]:
    return typing.cast(list[_InnerType], List(child_type, **kwargs))


def mapping(child_type: _InnerType, **kwargs) -> dict[str, _InnerType]:
    return typing.cast(dict[str, _InnerType], Mapping(child_type, **kwargs))


def compound(child_type: typing.Callable[..., _InnerType], **kwargs) -> _InnerType:
    return typing.cast(_InnerType, Compound(child_type, **kwargs))


def enum(values: typing.Iterable[str], **kwargs) -> str:
    return typing.cast(str, Enum(values, **kwargs))
