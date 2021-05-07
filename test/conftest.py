"""
Pytest configuration file, setup global pytest fixtures and functions here.
"""
import os
import time

from assemblyline.common import forge
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.datastore.stores.es_store import ESStore
from redis.exceptions import ConnectionError

import pytest
original_skip = pytest.skip

# Check if we are in an unattended build environment where skips won't be noticed
IN_CI_ENVIRONMENT = any(indicator in os.environ for indicator in
                        ['CI', 'BITBUCKET_BUILD_NUMBER', 'AGENT_JOBSTATUS'])


def skip_or_fail(message):
    """Skip or fail the current test, based on the environment"""
    if IN_CI_ENVIRONMENT:
        pytest.fail(message)
    else:
        original_skip(message)


# Replace the built in skip function with our own
pytest.skip = skip_or_fail


@pytest.fixture(scope='session')
def config():
    return forge.get_config()

  
@pytest.fixture(scope='module')
def elasticsearch_connection(config):

    store = ESStore(config.datastore.hosts)
    for _ in range(30):
        if store.ping():
            break
        time.sleep(1)
    else:
        pytest.skip("Could not connect to datastore")

    return store
  

@pytest.fixture(scope='module')
def datastore_connection(elasticsearch_connection):
    return AssemblylineDatastore(elasticsearch_connection)


@pytest.fixture(scope='session')
def redis_connection():
    from assemblyline.remote.datatypes import get_client
    c = get_client(None, None, False)
    try:
        ret_val = c.ping()
        if ret_val:
            return c
    except ConnectionError:
        pass

    return pytest.skip("Connection to the Redis server failed. This test cannot be performed...")
