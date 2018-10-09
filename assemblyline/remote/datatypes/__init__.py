#!/usr/bin/env python

import json
import logging
import redis
import time
import uuid


from datetime import datetime
from distutils.version import StrictVersion
from time import time


# Add a version warning if redis python client is < 2.10.0. Older versions
# have a connection bug that can manifest with the dispatcher.
if StrictVersion(redis.__version__) <= StrictVersion('2.10.0'):
    import warnings
    warnings.warn("%s works best with redis > 2.10.0. You're running"
                  " redis %s. You should upgrade." %
                  (__name__, redis.__version__))


log = logging.getLogger('assemblyline.queue')
pool = {}


def now_as_iso():
    s = datetime.utcfromtimestamp(time()).isoformat()
    return ''.join((s, 'Z'))


def reply_queue_name(suffix=None):
    components = [now_as_iso(), str(uuid.uuid4())]
    if suffix:
        components.append(str(suffix))
    return '.'.join(components)


def retry_call(func, *args, **kw):
    maximum = 2
    exponent = -7

    while True:
        try:
            return func(*args, **kw)
        except redis.ConnectionError:
            log.exception('Reconnect')
            time.sleep(2 ** exponent)
            exponent = exponent + 1 if exponent < maximum else exponent


def get_client(host, port, db, private):
    if not host or not port or not db:
        config = forge.get_config()
        host = host or config.core.redis.nonpersistent.host
        port = int(port or config.core.redis.nonpersistent.port)
        db = int(db or config.core.redis.nonpersistent.db)

    if private:
        return redis.StrictRedis(host=host, port=port, db=db)
    else:
        return redis.StrictRedis(connection_pool=get_pool(host, port, db))


def get_pool(host, port, db):
    key = (host, port, db)

    connection_pool = pool.get(key, None)
    if not connection_pool:
        connection_pool = \
            redis.BlockingConnectionPool(
                host=host,
                port=port,
                db=db,
                max_connections=200
            )
        pool[key] = connection_pool

    return connection_pool


# noinspection PyBroadException
def decode(data):
    try:
        return json.loads(data)
    except:  # pylint: disable=W0702
        log.warning("Invalid data on queue: %s", str(data))
        return None



