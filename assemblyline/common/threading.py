import elasticapm

from concurrent.futures import ThreadPoolExecutor
from elasticapm.traces import execution_context


def apm_monitored(fn, *args, **kwargs):
    with elasticapm.capture_span(fn.__name__, "threadpool"):
        return fn(*args, **kwargs)


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

    # Change the submit function so all subfunctions are monitored
    def submit(self, fn, /, *args, **kwargs):
        return super().submit(apm_monitored, fn, *args, **kwargs)
