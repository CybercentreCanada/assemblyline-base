import pytest

from assemblyline.common import forge
from assemblyline.common.testing import skip


KEY = "test1"
DATA = b"THIS IS WHAT I'LL SAVE INTO THE CACHE STORE..."
COMPONENT = "test_component"


@pytest.fixture(scope='module')
def cachestore():
    try:
        cachestore = forge.get_cachestore(COMPONENT)
        cachestore.datastore.cached_file.delete_matching("id:*")
        cachestore.save(KEY, DATA)
        cachestore.datastore.cached_file.commit()
    except ConnectionError:
        cachestore = None

    if cachestore:
        return cachestore

    return skip("Connection to the SOLR server failed. This test cannot be performed...")


def test_expiry_field(cachestore):
    assert cachestore.datastore.cached_file.search("expiry_ts:*", as_obj=False)['total'] == 1


def test_db_cache_entry(cachestore):
    key = f"{cachestore.component}_{KEY}"
    assert cachestore.datastore.cached_file.get(key, as_obj=False)['component'] == COMPONENT


def test_cache_data(cachestore):
    assert cachestore.get(KEY) == DATA


def test_cache_cleanup(cachestore):
    cachestore.delete(KEY)
    cachestore.datastore.cached_file.commit()

    assert cachestore.get(KEY) is None
    assert cachestore.datastore.cached_file.get(KEY, as_obj=False) is None
