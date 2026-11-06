"""
Pytest configuration file, setup global pytest fixtures and functions here.
"""
import os
import time
import uuid

from assemblyline.common import forge
from assemblyline.datastore.compat import SearchBackend, create_search_client
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


@pytest.fixture(scope='session')
def config():
    return forge.get_config()


@pytest.fixture(scope='module')
def filestore(config):
    try:
        return forge.get_filestore(config, connection_attempts=1)
    except ConnectionError as err:
        pytest.skip(str(err))


@pytest.fixture(scope='module')
def datastore_connection(config):
    ESCollection.MAX_RETRY_BACKOFF = 0.5
    store = ESStore(config.datastore.hosts)
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


@pytest.fixture
def opensearch_client(request):
    host = os.environ.get('AL_TEST_OPENSEARCH_HOST', 'http://127.0.0.1:9201')
    timeout = int(os.environ.get('AL_TEST_OPENSEARCH_TIMEOUT', '60'))
    deadline = time.monotonic() + timeout
    last_error = None

    while time.monotonic() < deadline:
        try:
            client = create_search_client(
                SearchBackend.OPENSEARCH,
                [host],
                max_retries=0,
                request_timeout=10,
                ca_certs=None,
                verify_certs=False,
            )
            if client.ping():
                break
            last_error = "ping returned false"
        except Exception as err:
            last_error = err
        time.sleep(1)
    else:
        pytest.fail(f"OpenSearch test service at {host} is not healthy after {timeout}s: {last_error}")

    index_prefix = f"al_os_test_{uuid.uuid4().hex}_"

    def make_index_name(name):
        return f"{index_prefix}{name}"

    client.make_index_name = make_index_name

    def cleanup():
        try:
            client.raw_client.indices.delete(index=f"{index_prefix}*", ignore_unavailable=True)
        finally:
            client.close()

    request.addfinalizer(cleanup)
    return client
