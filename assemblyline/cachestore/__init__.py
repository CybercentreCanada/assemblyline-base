
import re

from assemblyline.common import forge
from assemblyline.common.isotime import now_as_iso
from assemblyline.filestore import FileStore

DEFAULT_CACHE_LEN = 60 * 60  # 1 hour
COMPONENT_VALIDATOR = re.compile("^[a-zA-Z][a-zA-Z0-9_.]*$")

class CacheStore(object):
    def __init__(self, component, config=None, datastore=None):
        if not component:
            raise ValueError("Cannot instanciate a cachestore without providing a component name.")

        if not COMPONENT_VALIDATOR.match(component):
            raise ValueError("Invalid component name. (Only letters, numbers, underscores and dots allowed)")

        if config is None:
            config = forge.get_config()

        self.component = component
        self.datastore = datastore or forge.get_datastore()
        self.filestore = FileStore(*config.filestore.cache)

    def __enter__(self):
        return self

    def __exit__(self, ex_type, exc_val, exc_tb):
        self.filestore.close()

    def save(self, cache_key, data, ttl=DEFAULT_CACHE_LEN):
        if not COMPONENT_VALIDATOR.match(cache_key):
            raise ValueError("Invalid cache_key for cache item. "
                             "(Only letters, numbers, underscores and dots allowed)")

        new_key = f"{self.component}_{cache_key}" if self.component else cache_key

        self.datastore.cached_file.save(new_key, {'expiry_ts': now_as_iso(ttl), 'component': self.component})
        self.filestore.put(new_key, data)

    def get(self, cache_key):
        new_key = f"{self.component}_{cache_key}" if self.component else cache_key

        return self.filestore.get(new_key)

    def delete(self, cache_key, db_delete=True):
        new_key = f"{self.component}_{cache_key}" if self.component else cache_key

        self.filestore.delete(new_key)
        if db_delete:
            self.datastore.cached_file.delete(new_key)
