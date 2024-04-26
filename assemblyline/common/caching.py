from __future__ import annotations
import hashlib
import json
import threading
import time
import typing

from collections import OrderedDict
from typing import Generic, TypeVar, Hashable, Tuple, Optional

import baseconv

from assemblyline.common.uid import get_random_id


if typing.TYPE_CHECKING:
    from assemblyline.odm.messages.task import Task


T = TypeVar('T')


class TimeExpiredCache(Generic[T]):
    """
    TimeExpiredCache is a thread safe caching object that will store any amount of items for
    a period of X seconds at maximum.

    A thread inside the cache is fired every "expiry_rate" seconds and will remove all items that
    meet their timeouts.

    If you add the same item twice, the second time you add the item it will be ignored or can
    raise an exception if specified. This will not freshen the timeout for the specified item.
    """

    def __init__(self, timeout: float, expiry_rate: float = 5, raise_on_error: bool = False):
        self.lock = threading.Lock()
        self.timeout = timeout
        self.expiry_rate = expiry_rate
        self.raise_on_error = raise_on_error
        self.cache: dict[Hashable, T] = {}
        self.timeout_list: list[Tuple[float, Hashable]] = []
        timeout_thread = threading.Thread(target=self._process_timeouts, name="_process_timeouts", daemon=True)
        timeout_thread.start()

    def __len__(self):
        with self.lock:
            return len(self.cache)

    def __str__(self):
        with self.lock:
            return 'TimeExpiredCache(%s): %s' % (self.timeout, str(self.cache.keys()))

    def _process_timeouts(self):
        while True:
            time.sleep(self.expiry_rate)
            current_time = time.time()
            index = 0

            with self.lock:
                for t, k in self.timeout_list:
                    if t >= current_time:
                        break

                    index += 1

                    self.cache.pop(k, None)

                self.timeout_list = self.timeout_list[index:]

    def add(self, key: Hashable, data: T):
        with self.lock:
            if key in self.cache:
                if self.raise_on_error:
                    raise KeyError("%s already in cache" % key)
                else:
                    return

            self.cache[key] = data
            self.timeout_list.append((time.time() + self.timeout, key))

    @typing.overload
    def get(self, key: Hashable) -> Optional[T]:
        ...

    @typing.overload
    def get(self, key: Hashable, default: T) -> T:
        ...

    def get(self, key: Hashable, default: Optional[T] = None) -> Optional[T]:
        with self.lock:
            return self.cache.get(key, default)

    def keys(self):
        with self.lock:
            return self.cache.keys()


class SizeExpiredCache(Generic[T]):
    """
    SizeExpiredCache is a thread safe caching object that will store only X number of item for
    caching at maximum.

    If more items are added, the oldest item is removed.

    If you add the same item twice, the second time you add the item it will be ignored or can
    raise an exception if specified. This will not freshen the item position in the cache.
    """

    def __init__(self, max_item_count: int, raise_on_error: bool = False):
        self.lock = threading.Lock()
        self.max_item_count = max_item_count
        self.cache: OrderedDict[Hashable, T] = OrderedDict()
        self.raise_on_error = raise_on_error

    def __len__(self):
        with self.lock:
            return len(self.cache)

    def __str__(self):
        with self.lock:
            return 'SizeExpiredCache(%s/%s): %s' % (len(self.cache), self.max_item_count, str(self.cache.keys()))

    def add(self, key: Hashable, data: T):
        with self.lock:
            if key in self.cache:
                if self.raise_on_error:
                    raise KeyError("%s already in cache" % key)
                else:
                    return

            self.cache[key] = data
            if len(self.cache) > self.max_item_count:
                self.cache.popitem(False)

    @typing.overload
    def get(self, key: Hashable) -> Optional[T]:
        ...

    @typing.overload
    def get(self, key: Hashable, default: T) -> T:
        ...

    def get(self, key: Hashable, default: Optional[T] = None) -> Optional[T]:
        with self.lock:
            return self.cache.get(key, default)

    def keys(self):
        with self.lock:
            return self.cache.keys()


def generate_conf_key(service_tool_version: Optional[str] = None, task: Optional[Task] = None) -> str:
    ignore_salt = None
    service_config = None
    submission_params_str = None

    if task is not None:
        service_config = json.dumps(sorted(task.service_config.items()))
        submission_params = {
            "deep_scan": task.deep_scan,
            "max_files": task.max_files,
            "min_classification": task.min_classification.value,
            "ignore_filtering": task.ignore_filtering,
        }
        submission_params_str = json.dumps(sorted(submission_params.items()))

        if task.ignore_cache:
            ignore_salt = get_random_id()

    if service_tool_version is None and \
            service_config is None and \
            submission_params_str is None and \
            ignore_salt is None:
        return "0"

    total_str = f"{service_tool_version}_{service_config}_{submission_params_str}_{ignore_salt}".encode('utf-8')
    partial_md5 = hashlib.md5((str(total_str).encode('utf-8'))).hexdigest()[:16]
    return baseconv.base62.encode(int(partial_md5, 16))
