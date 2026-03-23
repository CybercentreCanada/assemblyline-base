import os.path
import operator
import datetime
import fnmatch
import re
import json
import threading
from typing import Any, Union, Optional
import logging
import random
import time
import asyncio
import ssl
import tempfile

import yaml
import aiohttp
import lark
import datemath
import arrow

from assemblyline.cachestore import CacheStore
from assemblyline.common.uid import get_random_id
from assemblyline.common.constants import CONFIG_HASH, POST_PROCESS_CONFIG_KEY
from assemblyline.odm import base as odm
from assemblyline.odm.models.actions import DEFAULT_POSTPROCESS_ACTIONS, PostprocessAction, Webhook
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.messages.submission import Submission as SubmissionMessage, from_datastore_submission
from assemblyline.odm.models.tagging import Tagging
from assemblyline.remote.datatypes.events import EventWatcher
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline.remote.datatypes.queues.priority import PriorityQueue
from assemblyline.remote.datatypes.hash import Hash


logger = logging.getLogger(__name__)

SubmissionKind = Union[Submission, SubmissionMessage]

ALERT_QUEUE_NAME = 'm-alert'
SUBMISSION_FIELDS = Submission.flat_fields()
TAG_FIELDS = Tagging.flat_fields()
RESTRICTED_FIELDS = {
    'sid',
    'max_score',
    'files',
    'metadata',
    'params'
}
RETRY_MAX_BACKOFF = 60


class WILDCARD:
    pass


class ParsingError(ValueError):
    pass


def get_values(value: Any, parts: list[str]) -> Any:
    while parts:
        if isinstance(value, list):
            for item in value:
                for out in get_values(item, list(parts)):
                    yield out
            return

        part = parts.pop(0)
        try:
            value = getattr(value, part)
        except AttributeError:
            try:
                value = value[part]
            except KeyError:
                return
    yield value


def get_values_from_tags(tags: list[dict[str, Any]], path: str) -> str:
    if path.startswith("tags."):
        path = path[5:]

    for entry in tags:
        if entry.get('type', '') == path:
            yield entry.get('value', '')


class NodeInterface:
    def test(self, sub: Submission, score: Optional[float] = None, tags: Optional[list[dict[str, Any]]] = None):
        raise NotImplementedError()

    def test_value(self, field, value):
        raise NotImplementedError()


class AndOperatorNode(NodeInterface):
    def __init__(self, args):
        self.args: list[NodeInterface] = args

    def __repr__(self):
        return f'({" AND ".join(repr(a) for a in self.args)})'

    def test(self, sub: Submission, score=None, tags: Optional[list[dict[str, Any]]] = None) -> bool:
        return all(arg.test(sub, score, tags) for arg in self.args)

    def test_value(self, field, value) -> bool:
        return all(arg.test_value(field, value) for arg in self.args)


class OrOperatorNode(NodeInterface):
    def __init__(self, args):
        self.args = args

    def __repr__(self):
        return f'({" OR ".join(repr(a) for a in self.args)})'

    def test(self, sub: Submission, score=None, tags: Optional[list[dict[str, Any]]] = None) -> bool:
        return any(arg.test(sub, score, tags) for arg in self.args)

    def test_value(self, field, value) -> bool:
        return any(arg.test_value(field, value) for arg in self.args)


class NotOperatorNode(NodeInterface):
    def __init__(self, arg):
        self.arg = arg

    def __repr__(self):
        return f'NOT {repr(self.arg)}'

    def test(self, sub: Submission, score=None, tags: Optional[list[dict[str, Any]]] = None) -> bool:
        return not self.arg.test(sub, score, tags)

    def test_value(self, field, value) -> bool:
        return not self.arg.test_value(value)


class PrefixOperation(NodeInterface):
    def type_check(self, x):
        return x

    def __init__(self, operation, arg):
        self.operation = operation
        self.arg = arg

    def __repr__(self):
        return f'({self.operation}, {repr(self.arg)})'

    def test_value(self, field, value):
        return self.operation(value, self.type_check(self.arg))


class StringPrefixOperation(PrefixOperation):
    pass


class NumberPrefixOperation(PrefixOperation):
    pass


class DatePrefixOperation(PrefixOperation):
    def type_check(self, x):
        return datemath.dm(x)


class Range(NodeInterface):
    def __init__(self, inclusive_start, first, end, inclusive_end):
        self.inclusive_start = inclusive_start
        self.inclusive_end = inclusive_end
        self.first = first
        self.end = end

    def __repr__(self):
        start = '[' if self.inclusive_start else '{'
        end = ']' if self.inclusive_end else '}'
        return f'{start}{self.first} TO {self.end}{end}'

    def parse_boundary(self, value):
        raise NotImplementedError()

    def parse_value(self, value):
        raise NotImplementedError()

    def test_value(self, field, value):
        try:
            value = self.parse_value(value)
            start = self.parse_boundary(self.first)
            end = self.parse_boundary(self.end)
        except (TypeError, ValueError):
            return False

        if self.inclusive_start:
            if value < start:
                return False
        else:
            if value <= start:
                return False

        if self.inclusive_end:
            if value > end:
                return False
        else:
            if value >= end:
                return False

        return True


class DateRange(Range):
    name = 'date'

    def parse_boundary(self, value):
        return datemath.dm(value)

    def parse_value(self, value):
        if isinstance(value, datetime.datetime):
            return value
        return arrow.get(value)


class NumberRange(Range):
    name = 'number'

    def parse_boundary(self, value):
        return float(value)

    def parse_value(self, value):
        return float(value)


class StringRange(Range):
    name = 'string'

    def parse_boundary(self, value):
        return str(value)

    def parse_value(self, value):
        return str(value)


class MatchOperation(NodeInterface):
    def __init__(self, value):
        self.search = value
        self.regex = False
        if len(self.search) >= 3 and self.search.startswith('/') and self.search.endswith('/'):
            pattern = self.search[1:-1]
            self.pattern = re.compile(pattern, flags=re.IGNORECASE | re.DOTALL)
            self.regex = True
        else:
            pattern = fnmatch.translate(self.search)
            if pattern.endswith('\\Z'):
                pattern = pattern[0:-2]
            # if pattern.startswith('(?s:') and pattern.endswith(")"):
            #     pattern = pattern[4:-1]
            pattern = f'(?:^|[^a-z]){pattern}(?:$|[^a-z])'
            self.pattern = re.compile(pattern, flags=re.IGNORECASE | re.DOTALL)

    def __repr__(self) -> str:
        return f'{self.search}'

    def test(self, sub: Submission, score=None, tags: Optional[list[dict[str, Any]]] = None):
        for path, field in SUBMISSION_FIELDS.items():
            if '__text__' in field.copyto:
                try:
                    for value in get_values(sub, path.split('.')):
                        if self.pattern.search(str(value)):
                            return True
                except (ValueError, TypeError):
                    pass
        if tags is not None:
            for path, field in TAG_FIELDS.items():
                if '__text__' in field.copyto:
                    try:
                        for value in get_values_from_tags(tags, path):
                            if self.pattern.search(str(value)):
                                return True
                    except (ValueError, TypeError):
                        pass
        return False

    def test_value(self, field, value):
        if self.regex:
            return bool(self.pattern.search(str(value)))
        if isinstance(field, odm.Text):
            return bool(self.pattern.search(str(value)))
        return fnmatch.fnmatch(str(value), self.search)


class NamedTest(NodeInterface):
    def __init__(self, name, field, value):
        self.name = name
        self.field = field
        self.value = value

    def __repr__(self) -> str:
        return f'{self.name}: {self.value}'

    def test(self, sub: Submission, score=None, tags=None):
        if self.name == 'max_score' and score is not None:
            return self.value.test_value(self.field, score)

        parts = self.name.split('.')
        if parts[0] == 'tags':
            if tags is None:
                return False
            for value in get_values_from_tags(tags, self.name):
                if self.value.test_value(self.field, value):
                    return True
        else:
            for value in get_values(sub, parts):
                if self.value.test_value(self.field, value):
                    return True
        return False


RANGE_TO_PREFIX = {
    DateRange: DatePrefixOperation,
    NumberRange: NumberPrefixOperation,
    StringRange: StringPrefixOperation
}


class ExpressionTransformer(lark.Transformer):
    """
    Takes a tree parsed from a lucene expression by lark, and turns it into
    operation objects that can be actually applied.
    """

    def __init__(self) -> None:
        super().__init__(visit_tokens=True)
        self.cache_safe = True

    def start(self, args):
        assert len(args) == 1
        return args[0]

    def term(self, args):
        self.cache_safe = False
        return self.field_term(args)

    def SIMPLE_TERM(self, value):
        out = []
        index = 0
        while index < len(value):
            if value[index] == '\\':
                if index + 1 < len(value):
                    out.append(value[index+1])
                else:
                    ValueError("Escape at end of term")
                index += 1
            else:
                out.append(value[index])
            index += 1
        return ''.join(out)

    def phrase_term(self, args):
        return str(args[0])[1:-1]

    def field_term(self, args):
        if len(args) == 2:
            if args[0] == '-' or args[0] == '+':
                raise ValueError("Boost terms not supported")

            op = {
                '<': operator.lt,
                '<=': operator.le,
                '>': operator.gt,
                '>=': operator.ge,
            }[args[0]]

            # Try to detect a number
            try:
                return NumberPrefixOperation(op, float(args[1]))
            except (ValueError, TypeError):
                pass

            try:
                datemath.dm(args[1])
                return DatePrefixOperation(op, args[1])
            except (arrow.ParserError, datemath.DateMathException):
                pass

            return StringPrefixOperation(op, str(args[1]))

        if len(args) == 1:
            return MatchOperation(args[0])
        raise ValueError()

    def REGEX_TERM(self, value):
        return MatchOperation(value)

    def field_expression(self, args):
        return self.expression(args)

    def expression(self, args):
        assert len(args) == 1
        return args[0]

    def field_or_expr(self, args):
        return self.or_expr(args)

    def or_expr(self, args):
        if len(args) == 1:
            return args[0]
        return OrOperatorNode(args)

    def field_and_expr(self, args):
        return self.and_expr(args)

    def and_expr(self, args):
        if len(args) == 1:
            return args[0]
        return AndOperatorNode(args)

    def field_not_expr(self, args):
        return self.not_expr(args)

    def not_expr(self, args):
        if len(args) == 2:
            return NotOperatorNode(args[1])
        if len(args) == 1:
            return args[0]
        raise ValueError()

    def atom(self, args):
        assert len(args) == 1
        return args[0]

    def field_atom(self, args):
        assert len(args) == 1
        return args[0]

    def field(self, args):
        assert len(args) == 2
        return NamedTest(args[0][0], args[0][1], args[1])

    def FIELD_LABEL(self, value):
        path = str(value)
        if not path.partition('.')[0] in RESTRICTED_FIELDS:
            self.cache_safe = False

        # Check if its a simple field
        field = SUBMISSION_FIELDS.get(value)
        if field:
            return (value, field)

        if not path.startswith('tags.'):
            # What if its a tag with a mapping
            while path:
                path, _, _ = path.rpartition('.')
                field = SUBMISSION_FIELDS.get(path, None)
                if isinstance(field, (odm.FlattenedObject, odm.Mapping)):
                    return value, field.child_type

        else:
            # Check if its a simple tag
            self.cache_safe = False
            _, _, path = path.partition('.')
            field = TAG_FIELDS.get(path)
            if field:
                return (value, field)

            # Make its a tag with a mapping in it
            while path:
                path, _, _ = path.rpartition('.')
                field = TAG_FIELDS.get(path, None)
                if isinstance(field, (odm.FlattenedObject, odm.Mapping)):
                    return value, field.child_type

        raise ParsingError(f"Unknown field: {value}")

    def field_value(self, args):
        assert len(args) == 1
        return args[0]

    def range(self, args):
        inc_start, first, end, inc_end = args

        if first == WILDCARD and end == WILDCARD:
            raise ValueError("A range can't be unlimited in both directions.")

        elif first == WILDCARD:
            kind, end = end
            if inc_end:
                return RANGE_TO_PREFIX[kind](operation=operator.le, arg=end)
            else:
                return RANGE_TO_PREFIX[kind](operation=operator.lt, arg=end)
        elif end == WILDCARD:
            kind, first = first
            if inc_start:
                return RANGE_TO_PREFIX[kind](operation=operator.ge, arg=first)
            else:
                return RANGE_TO_PREFIX[kind](operation=operator.gt, arg=first)
        else:
            kind1, value1 = first
            kind2, value2 = end

            if kind1 != kind2:
                raise ParsingError(f"Start and end of range {value1} TO {value2} "
                                   f"seen as different types {kind1.name} vs {kind2.name}")

            return kind1(
                inclusive_start=inc_start == '[',
                inclusive_end=inc_end == ']',
                first=value1,
                end=value2
            )

    def second_range_term(self, args: list[lark.Tree]):
        return self.first_range_term(args)

    def first_range_term(self, args: list[lark.Tree]):
        assert len(args) == 1
        return args[0]

    def RANGE_WILD(self, value):
        return WILDCARD

    def SECOND_RANGE(self, value):
        return self.FIRST_RANGE(value)

    def FIRST_RANGE(self, value):
        value = str(value).strip()

        # Try to detect a date range
        try:
            datemath.dm(value)
            return (DateRange, value)
        except (arrow.ParserError, datemath.DateMathException):
            pass

        # Try to detect a number
        try:
            return (NumberRange, float(value))
        except (ValueError, TypeError):
            pass

        return (StringRange, value)

    def QUOTED_RANGE(self, args):
        return (StringRange, str(args)[1:-1])

    def __default__(self, data, children, meta):
        print(data)
        print(children)
        print(meta)
        exit()


class SubmissionFilter:
    PARSER = lark.Lark.open(os.path.join(os.path.dirname(__file__), 'lucene.lark'))

    def __init__(self, expression: str):
        self.expression = expression
        trans = ExpressionTransformer()
        try:
            self.operation = trans.transform(self.PARSER.parse(expression))
        except lark.exceptions.VisitError as error:
            if isinstance(error.__context__, ParsingError):
                raise error.__context__
            else:
                raise
        self.cache_safe = trans.cache_safe

    def test(self, sub: SubmissionKind, score=None, tags: Optional[list[dict[str, Any]]] = None) -> bool:
        return self.operation.test(sub, score, tags)

    def __repr__(self) -> str:
        return '<SubmissionFilter ' + str(self.expression) + '>'


