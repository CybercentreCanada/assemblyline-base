from typing import Iterable


class SearchRetryException(Exception):
    pass


class DataStoreException(Exception):
    pass


class SearchException(Exception):
    pass


class SearchDepthException(Exception):
    pass


class UndefinedFunction(Exception):
    pass


class ILMException(Exception):
    pass


class MultiKeyError(KeyError):
    def __init__(self, keys: Iterable[str], partial_output):
        super().__init__(str(keys))
        self.keys = set(keys)
        self.partial_output = partial_output


