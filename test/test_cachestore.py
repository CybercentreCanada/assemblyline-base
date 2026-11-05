import uuid

import pytest

from assemblyline.common import forge


DATA = b"cache store test data"
COMPONENT = "test_component"
KEY = "test1"


@pytest.fixture(scope="module")
def cachestore(datastore_connection):
    cachestore = forge.get_cachestore(COMPONENT, datastore=datastore_connection)
    cachestore.datastore.cached_file.delete_by_query("id:*")
    cachestore.save(KEY, DATA)
    cachestore.datastore.cached_file.commit()
    return cachestore


@pytest.fixture
def cache_entry(datastore_connection):
    # Keep each test's backing-store key unique, then remove its file and metadata.
    cache = forge.get_cachestore(COMPONENT, datastore=datastore_connection)
    key = uuid.uuid4().hex

    yield cache, key

    cache.delete(key)
    cache.datastore.cached_file.commit()
    cache.filestore.close()


def test_expiry_field(cachestore):
    # Saved entries must be represented in the datastore expiry index.
    assert cachestore.datastore.cached_file.search("expiry_ts:*", as_obj=False)["total"] == 1


def test_db_cache_entry(cachestore):
    # The datastore record associates each entry with its owning component.
    key = f"{cachestore.component}_{KEY}"
    assert cachestore.datastore.cached_file.get(key, as_obj=False)["component"] == COMPONENT


def test_cache_data(cachestore):
    # A saved value must be retrievable through the CacheStore API.
    assert cachestore.get(KEY) == DATA


def test_cache_cleanup(cachestore):
    # Deletion removes both the cached bytes and the associated datastore entry.
    cachestore.delete(KEY)
    cachestore.datastore.cached_file.commit()

    assert cachestore.get(KEY) is None
    assert cachestore.datastore.cached_file.get(KEY, as_obj=False) is None


@pytest.mark.parametrize("component", ["", "invalid-component", "/path"])
def test_init_rejects_invalid_component(component):
    # Components prefix stored keys, so invalid names must be rejected at creation.
    with pytest.raises(ValueError, match="component"):
        forge.get_cachestore(component)


def test_save(cache_entry):
    # Save stores both the bytes and their component/expiry metadata.
    cache, key = cache_entry
    invalid_key = "invalid-key"

    # We expect an error for invalid keys
    with pytest.raises(ValueError, match="cache_key"):
        cache.save(invalid_key, DATA)

    cache.save(key, DATA, ttl=120, force=True)
    cache.datastore.cached_file.commit()

    metadata = cache.datastore.cached_file.get(f"{COMPONENT}_{key}", as_obj=False)
    assert metadata["component"] == COMPONENT
    assert metadata["expiry_ts"]
    assert cache.get(key) == DATA


def test_upload(cache_entry, tmp_path):
    # Upload provides the same cache entry semantics when the source is a local file.
    cache, key = cache_entry
    invalid_key = "invalid-key"
    source = tmp_path / "source"
    source.write_bytes(DATA)

    # We expect an error for invalid keys
    with pytest.raises(ValueError, match="cache_key"):
        cache.upload(invalid_key, str(source))

    # Upload the file to cache
    cache.upload(key, str(source), ttl=90)
    cache.datastore.cached_file.commit()

    # Check metadata exists and that an expiry is assigned and the data is correct
    metadata = cache.datastore.cached_file.get(f"{COMPONENT}_{key}", as_obj=False)
    assert metadata["component"] == COMPONENT
    assert metadata["expiry_ts"]
    assert cache.get(key) == DATA


def test_touch(cache_entry):
    # Touch must not create metadata on a miss, but should extend an existing entry.
    cache, key = cache_entry
    invalid_key = "invalid-key"

    # Should raise if key doesn't exist yet.
    with pytest.raises(KeyError, match=key):
        cache.touch(key)

    # Should raise for invalid key
    with pytest.raises(ValueError, match="cache_key"):
        cache.touch(invalid_key)

    # Save initial data under the key with a short TTL.
    cache.save(key, DATA, ttl=60)
    cache.datastore.cached_file.commit()
    old_expiry = cache.datastore.cached_file.get(f"{COMPONENT}_{key}", as_obj=False)["expiry_ts"]

    # Extend the lifetime of the cached entry
    cache.touch(key, ttl=3600)
    cache.datastore.cached_file.commit()
    new_expiry = cache.datastore.cached_file.get(f"{COMPONENT}_{key}", as_obj=False)["expiry_ts"]

    # New expiry should be later than old one and we should be able to get the data
    assert new_expiry > old_expiry
    assert cache.get(key) == DATA


def test_exists_and_download(cache_entry, tmp_path):
    # Read methods expose the cached bytes consistently, including file downloads.
    cache, key = cache_entry
    destination = tmp_path / "download"
    cache.save(key, DATA)

    assert cache.get(key) == DATA
    assert cache.exists(key)
    cache.download(key, str(destination))
    assert destination.read_bytes() == DATA


@pytest.mark.parametrize("db_delete", [True, False])
def test_delete(cache_entry, db_delete):
    # Default deletion removes both the cached file and its datastore record.
    cache, key = cache_entry
    cache.save(key, DATA)
    cache.datastore.cached_file.commit()

    cache.delete(key, db_delete)
    cache.datastore.cached_file.commit()

    assert cache.get(key) is None
    if not db_delete:
        # If db_delete is False, metadata should remain
        assert cache.datastore.cached_file.get(f"{COMPONENT}_{key}", as_obj=False) is not None
    else:
        # Otherwise, metadata should be gone too
        assert cache.datastore.cached_file.get(f"{COMPONENT}_{key}", as_obj=False) is None
