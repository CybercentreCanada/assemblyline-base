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
from assemblyline.odm import base as odm
from assemblyline.odm.models.actions import DEFAULT_POSTPROCESS_ACTIONS, PostprocessAction, Webhook
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.messages.submission import Submission as SubmissionMessage, from_datastore_submission
from assemblyline.odm.models.tagging import Tagging
from assemblyline.remote.datatypes.events import EventWatcher
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline.remote.datatypes.queues.priority import PriorityQueue


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


def get_values_from_tags(tags: list[dict], path: str) -> Any:
    if path.startswith("tags."):
        path = path[5:]

    for tag in tags:
        if tag['type'] == path:
            yield tag['value']


class NodeInterface:
    def test(self, sub: Submission, score=None, tags=None):
        raise NotImplementedError()

    def test_value(self, field, value):
        raise NotImplementedError()


class AndOperatorNode(NodeInterface):
    def __init__(self, args):
        self.args: list[NodeInterface] = args

    def __repr__(self):
        return f'({" AND ".join(repr(a) for a in self.args)})'

    def test(self, sub: Submission, score=None, tags=None) -> bool:
        for arg in self.args:
            if not arg.test(sub, score, tags):
                return False
        return True

    def test_value(self, field, value) -> bool:
        for arg in self.args:
            if not arg.test_value(field, value):
                return False
        return True


class OrOperatorNode(NodeInterface):
    def __init__(self, args):
        self.args = args

    def __repr__(self):
        return f'({" OR ".join(repr(a) for a in self.args)})'

    def test(self, sub: Submission, score=None, tags=None) -> bool:
        for arg in self.args:
            if arg.test(sub, score, tags):
                return True
        return False

    def test_value(self, field, value) -> bool:
        for arg in self.args:
            if arg.test_value(field, value):
                return True
        return False


class NotOperatorNode(NodeInterface):
    def __init__(self, arg):
        self.arg = arg

    def __repr__(self):
        return f'NOT {repr(self.arg)}'

    def test(self, sub: Submission, score=None, tags=None) -> bool:
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
        pattern = fnmatch.translate(self.search)
        if pattern.endswith('\\Z'):
            pattern = pattern[0:-2]
        # if pattern.startswith('(?s:') and pattern.endswith(")"):
        #     pattern = pattern[4:-1]
        pattern = f'(?:^|[^a-z]){pattern}(?:$|[^a-z])'
        self.pattern = re.compile(pattern, flags=re.IGNORECASE | re.DOTALL)

    def __repr__(self) -> str:
        return f'{self.search}'

    def test(self, sub: Submission, score=None, tags=None):
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

    def __init__(self, visit_tokens: bool = True) -> None:
        super().__init__(visit_tokens)
        self.cache_safe = True

    def start(self, args):
        assert len(args) == 1
        return args[0]

    def phrase_term(self, args):
        assert len(args) == 1
        return args[0]

    def term(self, args):
        self.cache_safe = False
        return self.field_term(args)

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

            try:
                datemath.dm(args[1])
                return DatePrefixOperation(op, args[1])
            except (arrow.ParserError, datemath.DateMathException):
                pass

            # Try to detect a number
            try:
                return NumberPrefixOperation(op, float(args[1]))
            except (ValueError, TypeError):
                pass

            return StringPrefixOperation(op, str(args[1]))

        if len(args) == 1:
            return MatchOperation(args[0])
        raise ValueError()

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

    def test(self, sub: SubmissionKind, score=None, tags: Optional[list[dict]] = None) -> bool:
        return self.operation.test(sub, score, tags)


def should_resubmit(score: float, shift: float = 500) -> bool:

    # Resubmit:
    #
    # 100%     with a score above 400.
    # 10%      with a score of 301 to 400.
    # 1%       with a score of 201 to 300.
    # 0.1%     with a score of 101 to 200.
    # 0.01%    with a score of 1 to 100.
    # 0.001%   with a score of 0.
    # 0%       with a score below 0.

    if score < 0:
        return False

    if score >= shift:
        return True

    resubmit_probability = 1.0 / 10 ** ((shift - score) / 100)

    return random.random() < resubmit_probability


class ActionWorker:
    def __init__(self, cache: bool, config, datastore, redis_persist) -> None:
        # Store parameters
        self.running_cache_tasks = cache

        # Setup dependencies
        self.config = config
        self.datastore = datastore

        # Submissions that should have alerts generated
        self.alert_queue: NamedQueue[dict] = NamedQueue(ALERT_QUEUE_NAME, redis_persist)
        self.unique_queue: PriorityQueue[dict] = PriorityQueue('m-unique', redis_persist)

        # Load actions
        self.actions: dict[str, tuple[SubmissionFilter, PostprocessAction]] = {}
        self._load_actions()

        # Make sure we load any changed actions
        self.reload_watcher: EventWatcher[str] = EventWatcher()
        self.reload_watcher.register('system.postprocess', self._load_actions)
        self.reload_watcher.start()

        # Create an event loop to handle highly parallel webhook calls
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, name='webhook_caller', daemon=True).start()

    def stop(self):
        self.reload_watcher.stop()
        while self.loop.is_running():
            if len(asyncio.all_tasks(self.loop)) == 0:
                break
            time.sleep(0.1)
        self.loop.call_soon_threadsafe(self.loop.stop)

    def _load_actions(self, _path=''):
        # Load the action data
        with CacheStore('system', config=self.config, datastore=self.datastore) as cache:
            objects = DEFAULT_POSTPROCESS_ACTIONS
            data = cache.get('postprocess_actions')
            if data:
                try:
                    raw = yaml.safe_load(data)
                    objects = {
                        key: PostprocessAction(data)
                        for key, data in raw.items()
                    }
                except Exception:
                    logger.exception("Couldn't load stored actions")

        # Check which ones can be active
        ready_objects = {}
        for key, data in objects.items():
            if not data.enabled:
                continue

            try:
                fltr = SubmissionFilter(data.filter)
            except Exception:
                logger.exception("Failed to load submission filter")
                continue

            if self.running_cache_tasks and data.run_on_cache:
                if not fltr.cache_safe:
                    logger.error("Tried to apply non-cache-safe filter to cached submissions.")
                    continue
                ready_objects[key] = fltr, data

            if not self.running_cache_tasks and data.run_on_completed:
                ready_objects[key] = fltr, data

        # Swap in the new actions
        self.actions = ready_objects

    def process_submission(self, submission: Submission, tags: list[dict]) -> bool:
        return self.process(submission=submission, tags=tags, score=submission.max_score)

    def process_cachehit(self, submission: SubmissionMessage, score: float) -> bool:
        return self.process(submission=submission, tags=None, score=score)

    def process(self, submission: Union[Submission, SubmissionMessage], score, tags) -> bool:
        """ Handle any postprocessing events for a submission.

        Return bool indicating if a resubmission action has happened.
        """
        create_alert = False
        resubmit: Optional[set[str]] = None
        webhooks = []

        for fltr, action in self.actions.values():
            if not fltr.test(submission, score=score, tags=tags):
                continue

            # Check if we need to launch an alert
            create_alert |= action.raise_alert

            # Accumulate resubmit services
            if action.resubmit is not None:
                do_resubmit = True
                if action.resubmit.random_below is not None:
                    do_resubmit = should_resubmit(score, action.resubmit.random_below)

                if do_resubmit:
                    if resubmit is None:
                        resubmit = set()
                    resubmit.update(set(action.resubmit.additional_services))

            # Accumulate hooks
            if action.webhook is not None and action.webhook not in webhooks:
                webhooks.append(action.webhook)

        # Bail early if nothing is to be done
        if resubmit is None and not create_alert and not webhooks:
            return False

        # Prepare a message formatted submission
        if isinstance(submission, Submission):
            submission_msg = from_datastore_submission(submission)
        else:
            submission_msg = submission

        # Trigger resubmit
        if submission.params.psid is None:
            extended_scan = 'skipped'
        else:
            # We are the extended scan
            extended_scan = 'submitted'
        did_resubmit = False

        if resubmit is not None:
            selected = set(submission.params.services.selected)
            resubmit_to = set(submission.params.services.resubmit) | resubmit

            if not selected.issuperset(resubmit_to):
                submit_to = sorted(selected | resubmit_to)
                extended_scan = 'submitted'

                logger.info(f"[{submission.sid} :: {submission.files[0].sha256}] Resubmitted for extended analysis")
                resubmission = SubmissionMessage(submission_msg.as_primitives())
                resubmission.params.psid = submission.sid
                resubmission.sid = get_random_id()
                resubmission.scan_key = None
                resubmission.params.services.resubmit = []
                resubmission.params.services.selected = submit_to

                self.unique_queue.push(submission.params.priority, dict(
                    score=score,
                    extended_scan=extended_scan,
                    ingest_id=submission.metadata.get('ingest_id', submission.sid),
                    submission=resubmission.as_primitives(),
                ))
                did_resubmit = True

        # Raise alert
        if submission.params.generate_alert and create_alert:
            logger.info(f"[{submission_msg.sid} :: {submission_msg.files[0].sha256}] Notifying alerter to "
                        "create or update an alert")

            self.alert_queue.push(dict(
                submission=submission_msg.as_primitives(),
                score=score,
                extended_scan=extended_scan,
                ingest_id=submission_msg.metadata.get('ingest_id', None)
            ))

        # Trigger webhooks
        for hook in webhooks:
            asyncio.run_coroutine_threadsafe(self._process_hook(hook, submission, score), self.loop)
        return did_resubmit

    async def _process_hook(self, hook: Webhook, submission: Union[Submission, SubmissionMessage], score: float):
        backoff = 0.0
        cafile = None

        try:
            is_cache = isinstance(submission, SubmissionMessage)
            payload = json.dumps({
                'is_cache': is_cache,
                'score': score,
                'submission': submission.as_primitives()
            })

            # Setup auth headers and other headers
            auth = None
            if hook.username and hook.password:
                auth = aiohttp.BasicAuth(login=hook.username, password=hook.password)
            headers = {head.name: head.value for head in hook.headers}
            headers.setdefault('Content-Type', 'application/json')

            # Setup ssl details
            sslcontext: Union[None, bool, ssl.SSLContext] = None
            if hook.ssl_ignore_errors:
                sslcontext = False
            if hook.ca_cert:
                cafile = tempfile.NamedTemporaryFile()
                cafile.write(hook.ca_cert.encode())
                cafile.flush()
                sslcontext = ssl.create_default_context(cafile=cafile.name)

            # Setup setup http query details
            async with aiohttp.ClientSession(auth=auth, headers=headers) as session:
                # Loop up to retry limit
                for _ in range(hook.retries):
                    # Wait before retrying, 0 first time, so we can have this before the post
                    # and not wait after the final failure
                    await asyncio.sleep(backoff)
                    backoff = min(RETRY_MAX_BACKOFF, backoff * 2) + 0.1

                    # Try posting to the webhook once. If it succeeds return and let
                    # the withs and finallys finish all the cleanup
                    try:
                        resp = await session.request(hook.method, hook.uri, data=payload,
                                                     ssl=sslcontext, proxy=hook.proxy)
                        resp.raise_for_status()
                        return
                    except Exception:
                        logger.exception(f"Error pushing to webhook: {hook}")

        except Exception:
            logger.exception(f"Error reading webhook configuration: {hook}")
        finally:
            if cafile is not None:
                cafile.close()
