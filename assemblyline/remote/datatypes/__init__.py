#!/usr/bin/env python

import json
import logging
import redis
import os
import time

from datetime import datetime
from packaging.version import parse


from assemblyline.common import forge
from assemblyline.common.uid import get_random_id

# Add a version warning if redis python client is < 2.10.0. Older versions
# have a connection bug that can manifest with the dispatcher.
if parse(redis.__version__) <= parse('2.10.0'):
    import warnings
    warnings.warn("%s works best with redis > 2.10.0. You're running"
                  " redis %s. You should upgrade." %
                  (__name__, redis.__version__))


log = logging.getLogger('assemblyline.queue')
pool = {}


def now_as_iso():
    s = datetime.utcfromtimestamp(time.time()).isoformat()
    return ''.join((s, 'Z'))


def reply_queue_name(prefix=None, suffix=None):
    if prefix:
        components = [prefix]
    else:
        components = []

    components.append(get_random_id())

    if suffix:
        components.append(str(suffix))

    return '-'.join(components)


def retry_call(func, *args, **kw):
    maximum = 2
    exponent = -7

    while True:
        try:
            ret_val = func(*args, **kw)

            if exponent != -7:
                log.info('Reconnected to Redis!')

            return ret_val

        except (redis.ConnectionError, ConnectionResetError) as ce:
            log.warning(f'No connection to Redis, reconnecting... [{ce}]')
            time.sleep(2 ** exponent)
            exponent = exponent + 1 if exponent < maximum else exponent


def _redis_ssl_kwargs(host: str) -> dict:
    redis_certs_path = os.environ.get('REDIS_CERTS_DIR', '/etc/assemblyline/ssl/')
    return dict(ssl_certfile=os.path.join(redis_certs_path, f'{host}.crt'),
                ssl_keyfile=os.path.join(redis_certs_path, f'{host}.key'),
                ssl_ca_certs=os.environ.get('REDIS_ROOT_CA_PATH', '/etc/assemblyline/ssl/al_root-ca.crt')
                )


def get_client(host, port, private):
    # In case a structure is passed a client as host
    config = forge.get_config()
    if isinstance(host, (redis.Redis, redis.StrictRedis)):
        if config.system.internal_encryption.enabled and not \
                any(['ssl' in kw for kw in host.connection_pool.connection_kwargs.keys()]):
            # If not configured to use internal encryption and it's enabled, then create a new client instance
            port = host.connection_pool.connection_kwargs['port']
            host = host.connection_pool.connection_kwargs['host']
        else:
            return host

    if not host or not port:
        host = host or config.core.redis.nonpersistent.host
        port = int(port or config.core.redis.nonpersistent.port)

    ssl_kwargs = {}
    if config.system.internal_encryption.enabled:
        ssl_kwargs = _redis_ssl_kwargs(host)
        ssl_kwargs['ssl'] = True

    if private:
        return redis.StrictRedis(host=host, port=port, socket_keepalive=True,
                                 **ssl_kwargs)
    else:
        return redis.StrictRedis(connection_pool=get_pool(host, port, ssl=ssl_kwargs.get('ssl', False)),
                                 socket_keepalive=True)


def get_pool(host, port, ssl=False):
    key = (host, port)
    connection_class = redis.connection.Connection
    connection_kwargs = {}
    if ssl:
        connection_class = redis.connection.SSLConnection
        connection_kwargs = _redis_ssl_kwargs(host)

    connection_pool = pool.get(key, None)
    if not connection_pool:
        connection_pool = \
            redis.BlockingConnectionPool(
                host=host,
                port=port,
                max_connections=200,
                connection_class=connection_class,
                **connection_kwargs
            )
        pool[key] = connection_pool

    return connection_pool


def decode(data):
    try:
        return json.loads(data)
    except ValueError:
        log.warning("Invalid data on queue: %s", str(data))
        return None
