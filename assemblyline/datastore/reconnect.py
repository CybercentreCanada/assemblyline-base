"""
Decorators to help make the datastore more reliable.

When the decorator is applied to a method, certain errors should result in
trying to reconnect to the datastore, before retrying the method.
"""
import elasticsearch
import requests
import riak
import time

from assemblyline.datastore.exceptions import SearchRetryException


class DatastoreClosedError(Exception):
    pass


def collection_reconnect(log):
    """Decorator for methods in collection objects."""
    return DatastoreReconnect(log=log, get_datastore=lambda x: x.datastore)


class DatastoreReconnect(object):
    RIAK_RECONNECT_MSGS = [
        "insufficient_vnodes",
        "Unknown message code: ",
        "all_nodes_down",
        "Socket returned short packet",
        "Not enough nodes are up to service this request.",
        "connected host has failed to respond",
        "target machine actively refused it",
        "timeout",
        "Connection refused",
        "Truncated message",
        "Truncated string",
        "Unexpected end-group tag",
        "unknown msg code",
        "key must be a string, instead got None",
        "Tag had invalid wire type",
        "returned zero bytes unexpectedly",
        "unexpected message code:",
        "Client is closed.",
        "established connection was aborted",
        "existing connection was forcibly closed"
    ]
    RIAK_ABORT_MSGS = [
        "too_large"
    ]
    MAX_RETRY_BACKOFF = 10

    def __init__(self, log=None, get_datastore=None):
        self.get_datastore = (lambda x: x) if get_datastore is None else get_datastore
        self.log = log

    def __call__(self, original):
        def wrapper(*args, **kw):
            ds = self.get_datastore(args[0])
            if ds.is_closed():
                raise DatastoreClosedError('You are trying to perform an operation on a close datastore')
            if ds.__class__.__name__ == "RiakStore":
                return riak_reconnect(ds, *args, **kw)
            elif ds.__class__.__name__ == "SolrStore":
                return solr_reconnect(ds, *args, **kw)
            elif ds.__class__.__name__ == "ESStore":
                return es_reconnect(ds, *args, **kw)

        def es_reconnect(ds, *args, **kwargs):
            retries = 0
            while True:
                try:
                    return original(*args, **kwargs)
                except SearchRetryException:
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    ds.connection_reset()
                    retries += 1

        def solr_reconnect(ds, *args, **kw):
            retries = 0
            while True:
                try:
                    return original(*args, **kw)
                except requests.RequestException:
                    if retries < self.MAX_RETRY_BACKOFF:
                        time.sleep(retries)
                    else:
                        time.sleep(self.MAX_RETRY_BACKOFF)
                    ds.connection_reset()
                    retries += 1

        def riak_reconnect(ds, *args, **kw):
            retries = 0
            while True:
                try:
                    return original(*args, **kw)
                except OverflowError:
                    ds.connection_reset()
                    retries += 1
                except riak.RiakError as e:
                    error = str(e)
                    if any(msg in error for msg in self.RIAK_ABORT_MSGS):
                        raise
                    ds.connection_reset()
                    retries += 1
                except Exception as e:
                    error = str(e)
                    re_raise = True
                    if any(msg in error for msg in self.RIAK_RECONNECT_MSGS):
                        if retries < self.MAX_RETRY_BACKOFF:
                            time.sleep(retries)
                        else:
                            time.sleep(self.MAX_RETRY_BACKOFF)
                        if self.log and retries % 10 == 0:
                            self.log.debug("Reconnecting to riak: %s", error)
                        ds.connection_reset()
                        re_raise = False

                    if re_raise:
                        raise
                    else:
                        retries += 1

        # Make this a well-behaved decorator.
        wrapper.__name__ = original.__name__
        wrapper.__doc__ = original.__doc__
        wrapper.__dict__.update(original.__dict__)

        return wrapper
