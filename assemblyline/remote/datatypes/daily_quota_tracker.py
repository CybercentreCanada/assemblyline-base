from assemblyline.common.isotime import now_as_iso
from assemblyline.remote.datatypes import get_client, retry_call


class DailyQuotaTracker(object):
    def __init__(self, redis=None, host=None, port=None, private=False):
        self.c = redis or get_client(host, port, private)
        self.ttl = 60*60*24

    def _counter_name(self, user, type):
        return f"DAILY-QUOTA-{now_as_iso()[:10]}-{user}-{type}"

    def _decrement(self, user, type):
        counter = self._counter_name(user, type)
        with self.c.pipeline() as pipe:
            pipe.decr(counter)
            pipe.expire(counter, self.ttl, nx=True)

            val, _ = retry_call(pipe.execute)

        return val

    def decrement_api(self, user):
        return self._decrement(user, 'api')

    def decrement_submission(self, user):
        return self._decrement(user, 'submission')

    def _increment(self, user, type):
        counter = self._counter_name(user, type)
        with self.c.pipeline() as pipe:
            pipe.incr(counter)
            pipe.expire(counter, self.ttl, nx=True)

            val, _ = retry_call(pipe.execute)

        return val

    def increment_api(self, user):
        return self._increment(user, 'api')

    def increment_submission(self, user):
        return self._increment(user, 'submission')

    def _get(self, user, type):
        counter = self._counter_name(user, type)
        return retry_call(self.c.get, counter) or 0

    def get_api(self, user):
        return int(self._get(user, 'api'))

    def get_submission(self, user):
        return int(self._get(user, 'submission'))
