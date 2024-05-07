from assemblyline.common.isotime import now_as_iso
from assemblyline.remote.datatypes import get_client, retry_call


class DailyQuotaTracker(object):
    def __init__(self, redis=None, host=None, port=None, private=False):
        self.c = redis or get_client(host, port, private)
        self.ttl = 60*60*24

    def _counter_name(self, user, type):
        return f"DAILY-QUOTA-{now_as_iso()[:10]}-{user}-{type}"

    def _increment(self, user, type):
        counter = self._counter_name(user, type)
        val = retry_call(self.c.incr, counter)

        # Set the expiry only for the first call of the day
        if val == 1:
            retry_call(self.c.expire, counter, self.ttl)

        return val

    def increment_api(self, user):
        return self._increment(user, 'api')

    def increment_submission(self, user):
        return self._increment(user, 'submission')
