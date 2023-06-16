import re

from assemblyline.common.isotime import (
    LOCAL_FMT_WITH_MS,
    ensure_time_format,
    epoch_to_iso,
    epoch_to_local,
    epoch_to_local_with_ms,
    iso_to_epoch,
    local_to_epoch,
    local_to_local_with_ms,
    local_with_ms_to_epoch,
    now,
    now_as_iso,
    now_as_local,
)


def test_isotime_iso():
    iso_date = now_as_iso()
    iso_format = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z')

    assert isinstance(iso_date, str)
    assert iso_format.match(iso_date)
    assert epoch_to_iso(iso_to_epoch(iso_date)) == iso_date
    assert iso_date == epoch_to_iso(local_with_ms_to_epoch(epoch_to_local_with_ms(local_to_epoch(epoch_to_local(iso_to_epoch(iso_date))))))


def test_isotime_local():
    local_date = now_as_local()
    local_format = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}.*')

    assert isinstance(local_date, str)
    assert local_format.match(local_date)
    assert epoch_to_local(local_to_epoch(local_date)) == local_date
    assert epoch_to_local_with_ms(local_with_ms_to_epoch(local_date)) == local_date
    assert local_date == epoch_to_local(iso_to_epoch(epoch_to_iso(local_to_epoch(local_date))))


def test_isotime_epoch():
    epoch_date = now(200)
    assert epoch_date == local_to_epoch(epoch_to_local(epoch_date))
    assert epoch_date == local_with_ms_to_epoch(epoch_to_local_with_ms(epoch_date))
    assert epoch_date == iso_to_epoch(epoch_to_iso(epoch_date))

    assert isinstance(epoch_date, float)


def test_isotime_rounding_error():
    for t in ["2020-01-29 18:41:25.758416", "2020-01-29 18:41:25.127600"]:
        epoch = local_to_epoch(t)
        local = epoch_to_local(epoch)
        assert local == t

def test_local_to_local_with_ms():
    local_date = now_as_local()
    assert local_to_local_with_ms(local_date) == local_date[:-3]

def test_ensure_time_format():
    local_date = now_as_local()
    assert ensure_time_format(local_date, LOCAL_FMT_WITH_MS)
