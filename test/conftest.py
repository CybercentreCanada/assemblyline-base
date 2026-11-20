"""
Pytest configuration file, setup global pytest fixtures and functions here.
"""
import os

from assemblyline.common import forge
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.datastore.store import ESStore, ESCollection
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


@pytest.fixture(scope='session', params=["elasticsearch", "opensearch"])
def config(request):
    config = forge.get_config()
    config.datastore.type = request.param
    if request.param == "opensearch":
        # Use opensearch host
        config.datastore.hosts = ["http://localhost:9201"]
    else:
        # Use elasticsearch host
        config.datastore.hosts = ["http://elastic:devpass@localhost:9200"]
    return config


@pytest.fixture(scope='module')
def filestore(config):
    try:
        return forge.get_filestore(config, connection_attempts=1)
    except ConnectionError as err:
        pytest.skip(str(err))

@pytest.fixture(scope='module')
def datastore_connection(config):
    ESCollection.MAX_RETRY_BACKOFF = 0.5
    store = ESStore(config.datastore.hosts, backend=config.datastore.type)
    ret_val = store.ping()
    if not ret_val:
        pytest.skip("Could not connect to datastore")

    return AssemblylineDatastore(store)


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
