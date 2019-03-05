from assemblyline.common import forge
from assemblyline.common.isotime import now_as_iso
from assemblyline.filestore import FileStore

DEFAULT_CACHE_LEN = 60 * 60  # 1 hour


class CacheStore(object):
    def __init__(self, component, config=None, datastore=None):
        if config is None:
            config = forge.get_config()

        self.datastore = datastore or forge.get_datastore()
        self.filestore = FileStore(*config.filestore.cache)
        self.component = component

    def __enter__(self):
        return self

    def __exit__(self, ex_type, exc_val, exc_tb):
        self.filestore.close()

    def save(self, cache_key, data, ttl=DEFAULT_CACHE_LEN):
        new_key = f"{self.component}_{cache_key}" if self.component else cache_key

        self.datastore.cached_file.save(new_key, {'expiry_ts': now_as_iso(ttl), 'component': self.component})
        self.filestore.save(new_key, data)

    def get(self, cache_key):
        new_key = f"{self.component}_{cache_key}" if self.component else cache_key

        return self.filestore.get(new_key)

    def delete(self, cache_key, db_delete=True):
        new_key = f"{self.component}_{cache_key}" if self.component else cache_key

        self.filestore.delete(new_key)
        if db_delete:
            self.datastore.cached_file.delete(new_key)
