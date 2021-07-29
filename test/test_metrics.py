import time

import pytest

from assemblyline.common.metrics import MetricsFactory, PerformanceTimer
from assemblyline import odm
from assemblyline.common import forge


@odm.model()
class Metrics(odm.Model):
    counter = odm.Integer()
    performance_counter = PerformanceTimer()


def test_metrics_counter(redis_connection):
    source = MetricsFactory('test', Metrics, redis=redis_connection)

    channel = forge.get_metrics_sink(redis_connection)
    channel.listen(blocking=False)

    source.increment('counter', 55)
    source.increment_execution_time('performance_counter', 6)
    source.increment_execution_time('performance_counter', 6)

    start = time.time()
    read = {}
    for metric_message in channel.listen(blocking=False):
        if time.time() - start > 30:
            pytest.fail()

        if metric_message is None:
            time.sleep(0.1)
            continue

        if 'counter' in read and 'performance_counter.t' in read:
            break

        for key, value in metric_message.items():
            if isinstance(value, (int, float)):
                read[key] = read.get(key, 0) + value

    assert read['counter'] == 55
    assert read['performance_counter.t'] == 12
    assert read['performance_counter.c'] == 2

    source.stop()
