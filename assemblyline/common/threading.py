
from concurrent.futures import ThreadPoolExecutor
from elasticapm.traces import execution_context


class APMAwareThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, **kwargs):
        # If an APM server is defined we will get the current transaction
        self.apm_transaction = execution_context.get_transaction()

        super().__init__(initializer=self._set_apm_transaction, **kwargs)

    def _set_apm_transaction(self):
        # Make sure the context is set in each threads
        if self.apm_transaction is not None:
            execution_context.set_transaction(self.apm_transaction)
