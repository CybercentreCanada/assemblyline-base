from datetime import datetime
from time import time

EPOCH = datetime.utcfromtimestamp(0)
ISO_FMT = '%Y-%m-%dT%H:%M:%S'
LOCAL_FMT = '%Y-%m-%d %H:%M:%S'

# DO NOT REMOVE!!! THIS IS MAGIC!
# strptime Thread safe fix... yeah ...
datetime.strptime("2000", "%Y")
# END OF MAGIC


def _epoch_to_ms(t):
    try:
        return str(t - int(t))[1:]
    except (ValueError, IndexError, TypeError):
        return ''


def _timestamp_to_ms(ts):
    try:
        start = ts.find('.')
        end = ts.find('Z')
        if end == -1:
            end = len(ts)

        return float(ts[start:end])
    except (AttributeError, ValueError, IndexError, TypeError):
        return 0.0


def epoch_to_iso(t):
    s = datetime.utcfromtimestamp(t).isoformat()
    return ''.join((s, 'Z'))


def epoch_to_local(t):
    s = datetime.fromtimestamp(t).strftime(LOCAL_FMT)
    return ''.join((s, _epoch_to_ms(t)))[:26]


def iso_to_epoch(ts, hp=False):
    if not ts:
        return 0
    dt = datetime.strptime(ts[:19], ISO_FMT)
    if hp:
        return int(((dt - EPOCH).total_seconds() + _timestamp_to_ms(ts)) * 1000000)
    else:
        return (dt - EPOCH).total_seconds() + _timestamp_to_ms(ts)


def iso_to_local(ts):
    return epoch_to_local(iso_to_epoch(ts))


def local_to_epoch(ts, hp=False):
    epoch = iso_to_epoch("%sZ" % ts.replace(" ", "T"))
    if hp:
        return int((epoch + (utc_offset_from_local(epoch) * 3600)) * 1000000)
    else:
        return epoch + (utc_offset_from_local(epoch) * 3600)


def local_to_iso(ts):
    return epoch_to_iso(local_to_epoch(ts))


def now(offset=0.0):
    return time() + offset


def now_as_iso(offset=0.0):
    return epoch_to_iso(now(offset))


def now_as_local(offset=0.0):
    return epoch_to_local(now(offset))


def utc_offset_from_local(cur_time=None):
    if not cur_time:
        cur_time = time()
    return int(cur_time - iso_to_epoch("%sZ" % epoch_to_local(cur_time).replace(" ", "T"))) / 3600


def trunc_day(timeobj):
    """Truncate a datetime object to the nearest day."""
    return timeobj.replace(hour=0, minute=0, second=0, microsecond=0)


def format_time(timeobj):
    """Format a datetime object to the specific iso UTC string the datastore desires."""
    # Strip out any existing time zone data, because the time zone formatting
    # isoformat uses by default is offset based, rather than suffex code '+0' vs 'Z'
    timeobj = timeobj.replace(tzinfo=None)

    # Put it in a timezone missing iso simulation, then add the zulu 'Z'
    return timeobj.isoformat() + 'Z'
