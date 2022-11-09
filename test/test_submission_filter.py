from copy import deepcopy
import time

import datemath
from assemblyline.odm.models.actions import PostprocessAction, Webhook

from assemblyline.odm.randomizer import random_minimal_obj
from assemblyline.odm.models.submission import Submission, File
from assemblyline.odm.messages.submission import Submission as MessageSubmission

from assemblyline.common.postprocess import ActionWorker, SubmissionFilter, ParsingError


def test_simple_filters():
    sub: Submission = random_minimal_obj(Submission)
    sub.max_score = 100
    sub.times.completed = time.time()

    fltr = SubmissionFilter("times.completed: [now-1d TO 2025-06-20T10:10:10.000] AND max_score: [10 TO 100]")
    assert not fltr.cache_safe

    assert fltr.test(sub)
    sub.max_score = 101
    assert not fltr.test(sub)
    sub.max_score = 11
    assert fltr.test(sub)
    sub.times.completed = datemath.dm('now-2d')
    assert not fltr.test(sub)

    fltr = SubmissionFilter("max_score: {10 TO 100} OR metadata.stuff: {\"big cats\" TO cats}")
    assert fltr.cache_safe

    assert fltr.test(sub)
    sub.max_score = 10
    assert not fltr.test(sub)
    sub.metadata['stuff'] = 'cats'
    assert not fltr.test(sub)
    sub.metadata['stuff'] = 'big dogs'
    assert fltr.test(sub)

    fltr = SubmissionFilter('max_score: >100 AND NOT results: *virus*')
    assert not fltr.cache_safe

    assert not fltr.test(sub)
    sub.results = ['a-virus-service']
    sub.max_score = 101
    assert not fltr.test(sub)
    sub.results = ['a-something-service']
    assert fltr.test(sub)

    fltr = SubmissionFilter('files.size:>100')
    assert fltr.cache_safe

    sub.files = []
    assert not fltr.test(sub)
    sub.files.append(File({'name': 'abc', 'size': 100, 'sha256': '0' * 64}))
    assert not fltr.test(sub)
    sub.files.append(File({'name': 'abc', 'size': 101, 'sha256': '0' * 64}))
    assert fltr.test(sub)

    fltr = SubmissionFilter("metadata.stuff: (things OR stuff) AND cats")
    assert not fltr.cache_safe

    assert not fltr.test(sub)
    sub.params.description = "Full of cats."
    assert not fltr.test(sub)
    sub.metadata['stuff'] = "things"
    assert fltr.test(sub)


def test_bad_field_detection():
    try:
        SubmissionFilter("max_score.pain:found")
        assert False
    except ParsingError as error:
        assert 'max_score' in str(error)
        assert 'pain' in str(error)

    try:
        SubmissionFilter("max_score_pain: found")
        assert False
    except ParsingError as error:
        assert 'max_score_pain' in str(error)


def test_tag_filters():
    sub: Submission = random_minimal_obj(Submission)
    sub.max_score = 100

    tags = [
        {'safelisted': False, 'type': 'vector', 'value': 'things', 'short_type': 'vector'},
        {'safelisted': False, 'type': 'technique.packer', 'value': 'giftwrap', 'short_type': 'packer'}
    ]

    fltr = SubmissionFilter("max_score: >=100 AND tags.vector: *")
    assert not fltr.cache_safe

    assert not fltr.test(sub)
    assert fltr.test(sub, tags=tags)

    fltr = SubmissionFilter("max_score: >=100 AND things")
    assert not fltr.cache_safe

    assert not fltr.test(sub)
    assert fltr.test(sub, tags=tags)

    fltr = SubmissionFilter("max_score: >=100 AND things AND giftwrap")
    assert not fltr.cache_safe

    assert not fltr.test(sub)
    assert fltr.test(sub, tags=tags)

    fltr = SubmissionFilter("max_score: >=100 AND tags.technique.packer: *wrap")
    assert not fltr.cache_safe

    assert not fltr.test(sub)
    assert fltr.test(sub, tags=tags)


def test_message_filter():
    sub: MessageSubmission = random_minimal_obj(MessageSubmission)

    fltr = SubmissionFilter("max_score: [500 TO *] AND metadata.stream: (10 OR 99)")
    assert fltr.cache_safe

    assert not fltr.test(sub, score=100)
    assert not fltr.test(sub, score=600)

    sub.metadata['stream'] = "99"

    assert not fltr.test(sub, score=100)
    assert fltr.test(sub, score=600)


def test_regex_filter():
    sub: MessageSubmission = random_minimal_obj(MessageSubmission)

    fltr = SubmissionFilter("metadata.other: /ab+c/")
    print(fltr)
    assert fltr.cache_safe

    assert not fltr.test(sub)

    sub.metadata['other'] = "ac"
    assert not fltr.test(sub)

    sub.metadata['other'] = "abbbc"
    assert fltr.test(sub)


def test_webhook_match():

    webhook_first = dict(
        password=None,
        private_key=None,
        ca_cert=None,
        ssl_ignore_errors=False,
        proxy=None,
        uri="http://api.interface.website",
        username=None,
        headers=[]
    )

    webhook_second = deepcopy(webhook_first)
    webhook_second['headers'].append({
        'name': 'APIKEY',
        'value': '1'*64
    })

    a = Webhook(webhook_first)
    b = Webhook(webhook_first)
    c = Webhook(webhook_second)

    assert a == b
    assert a != c
    assert a in [b]
    assert a not in [c]
