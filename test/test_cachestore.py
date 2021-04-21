import pytest

from assemblyline.common import forge


KEY = "test1"
DATA = b"THIS IS WHAT I'LL SAVE INTO THE CACHE STORE..."
COMPONENT = "test_component"


@pytest.fixture(scope='module')
def cachestore(datastore_connection):
    cachestore = forge.get_cachestore(COMPONENT, datastore=datastore_connection)
    cachestore.datastore.cached_file.delete_by_query("id:*")
    cachestore.save(KEY, DATA)
    cachestore.datastore.cached_file.commit()

    return cachestore


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
