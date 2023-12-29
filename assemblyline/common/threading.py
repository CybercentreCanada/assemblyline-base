import types
import elasticapm

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import BrokenThreadPool, _global_shutdown_lock, _shutdown
from concurrent.futures import _base

from elasticapm.traces import execution_context


class APMAwareThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, *args, **kwargs):
        # If an APM server is defined we will get the current transaction
        self.apm_transaction = execution_context.get_transaction()

        # You are not allowed to use the following
        kwargs.pop("initializer", None)

        super().__init__(initializer=self._set_apm_transaction, *args, **kwargs)

    def _set_apm_transaction(self):
        # Make sure the context is set in each threads
        if self.apm_transaction is not None:
            execution_context.set_transaction(self.apm_transaction)

    # This is a carbon copy of the original TPE submit function that uses the new WorkItem class
    #  ** DO NOT MODIFY **
    def submit(self, fn, /, *args, **kwargs):
        with self._shutdown_lock, _global_shutdown_lock:
            if self._broken:
                raise BrokenThreadPool(self._broken)

            if self._shutdown:
                raise RuntimeError('cannot schedule new futures after shutdown')
            if _shutdown:
                raise RuntimeError('cannot schedule new futures after '
                                   'interpreter shutdown')

            f = _base.Future()
            w = _WorkItem(f, fn, args, kwargs)

            self._work_queue.put(w)
            self._adjust_thread_count()
            return f


# This is an updated WorkItem class that adds aupport for ElasticAPM Span
class _WorkItem(object):
    def __init__(self, future, fn, args, kwargs):
        self.future = future
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        if not self.future.set_running_or_notify_cancel():
            return

        try:
            with elasticapm.capture_span(self.fn.__name__, "threadpool"):
                result = self.fn(*self.args, **self.kwargs)
        except BaseException as exc:
            self.future.set_exception(exc)
            # Break a reference cycle with the exception 'exc'
            self = None
        else:
            self.future.set_result(result)

    __class_getitem__ = classmethod(types.GenericAlias)
