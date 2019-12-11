import json
import logging
import logging.handlers
import uuid
import string
from queue import Queue

import pytest

from assemblyline.common.logformat import AL_JSON_FORMAT
from assemblyline.common.log import JsonFormatter


@pytest.fixture
def json_logger():
    logger = logging.Logger(name=uuid.uuid4().hex)
    while logger.handlers:
        logger.removeHandler(logger.handlers[0])

    queue = Queue()
    logger.addHandler(logging.handlers.QueueHandler(queue))
    logger.handlers[0].setFormatter(JsonFormatter(AL_JSON_FORMAT))

    yield logger, queue


def test_null_messages(json_logger):
    logger, queue = json_logger
    logger.info(None)
    record = queue.get()
    out_msg = json.loads(record.message)
    assert out_msg['message'] == 'None'


def test_empty_messages(json_logger):
    logger, queue = json_logger
    msg = ''
    logger.info(msg)
    record = queue.get()
    out_msg = json.loads(record.message)
    assert out_msg['message'] == msg


def test_simple_messages(json_logger):
    logger, queue = json_logger
    msg = 'abc 123 message with text'
    logger.info(msg)
    record = queue.get()
    out_msg = json.loads(record.message)
    assert out_msg['message'] == msg


def test_simple_obj_messages(json_logger):
    logger, queue = json_logger
    msg = {"cat": 123}
    logger.info(msg)
    record = queue.get()
    out_msg = json.loads(record.message)
    assert out_msg['message'] == str(msg)


def test_simple_json_messages(json_logger):
    logger, queue = json_logger
    msg = {"cat": 123}
    logger.info(json.dumps(msg))
    record = queue.get()
    out_msg = json.loads(record.message)
    assert json.loads(out_msg['message']) == msg


def test_punctuation_messages(json_logger):
    logger, queue = json_logger
    msg = string.punctuation
    logger.info(msg)
    record = queue.get()
    out_msg = json.loads(record.message)
    assert out_msg['message'] == msg


def test_trace_message(json_logger):
    logger, queue = json_logger
    try:
        None.attribute
    except AttributeError:
        logger.exception('expected error')
    record = queue.get()
    out_msg = json.loads(record.message)
    assert 'expected error' in out_msg['message']
    assert 'Traceback' in out_msg['message']


def test_json_message(json_logger):
    logger, queue = json_logger
    log_obj = {'abc': r"xxx\"xxx", '123': string.punctuation}
    try:
        None.attribute
    except AttributeError:
        logger.exception(json.dumps(log_obj))
    record = queue.get()
    out_msg = json.loads(record.message)
    assert json.dumps(log_obj) in out_msg['message']
    assert 'Traceback' in out_msg['message']


def test_printable_messages(json_logger):
    logger, queue = json_logger
    msg = string.printable
    logger.info(msg)
    record = queue.get()
    out_msg = json.loads(record.message)
    # Make sure the important things are still there
    assert string.ascii_letters in out_msg['message']
    assert string.digits in out_msg['message']
    assert string.punctuation in out_msg['message']
