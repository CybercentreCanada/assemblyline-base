from datetime import datetime
from time import time
from typing import Optional

EPOCH = datetime.utcfromtimestamp(0)
ISO_FMT = '%Y-%m-%dT%H:%M:%S'
LOCAL_FMT = '%Y-%m-%d %H:%M:%S'
LOCAL_FMT_WITH_MS = f"{LOCAL_FMT}.%f"
DB_FMT = '%Y%m%d'

MAX_TIME = datetime.max
MIN_TIME = datetime.min

# DO NOT REMOVE!!! THIS IS MAGIC!
# strptime Thread safe fix... yeah ...
datetime.strptime("2000", "%Y")
# END OF MAGIC


def _epoch_to_ms(t: float) -> str:
    try:
        # We cannot ensure that float operation will preserve the digit properly therefore we can't do this:
        #         return str(t - int(t))[1:]
        # Let's do string manipulation instead...

        ms = ".%s" % repr(t).split(".")[1]
        if len(ms) < 7:
            ms += "0" * (7 - len(ms))
        return ms[:7]

    except (ValueError, IndexError, TypeError):
        return ''


def _timestamp_to_ms(ts: str) -> float:
    try:
        start = ts.find('.')
        end = ts.find('Z')
        if end == -1:
            end = len(ts)

        return float(ts[start:end])
    except (AttributeError, ValueError, IndexError, TypeError):
        return 0.0


def epoch_to_iso(t: float) -> str:
    s = datetime.utcfromtimestamp(t).isoformat()
    return ''.join((s, 'Z'))


def epoch_to_local(t: float) -> str:
    s = format_time(datetime.fromtimestamp(t), LOCAL_FMT)
    return ''.join((s, _epoch_to_ms(t)))[:26]


def epoch_to_local_with_ms(t: float, trunc: int = 0) -> str:
    s = format_time(datetime.fromtimestamp(t), LOCAL_FMT_WITH_MS)
    if trunc:
        # We don't need precision to the nano second. Milliseconds work just fine. Set trunc=3.
        s = s[:-1*trunc]
    return s


def iso_to_epoch(ts: str, hp: bool = False) -> float:
    if not ts:
        return 0
    dt = datetime.strptime(ts[:19], ISO_FMT)
    if hp:
        return int(((dt - EPOCH).total_seconds() + _timestamp_to_ms(ts)) * 1000000)
    else:
        return (dt - EPOCH).total_seconds() + _timestamp_to_ms(ts)


def iso_to_local(ts: str) -> str:
    return epoch_to_local(iso_to_epoch(ts))


def local_to_epoch(ts: str, hp: bool = False) -> float:
    epoch = iso_to_epoch("%sZ" % ts.replace(" ", "T"))
    if hp:
        return int((epoch + (utc_offset_from_local(epoch) * 3600)) * 1000000)
    else:
        return epoch + (utc_offset_from_local(epoch) * 3600)


def local_with_ms_to_epoch(ts: str, hp: bool = False) -> float:
    epoch = iso_to_epoch("%sZ" % ts.replace(" ", "T"))
    if hp:
        return int((epoch + (utc_offset_from_local_with_ms(epoch) * 3600)) * 1000000)
    else:
        return epoch + (utc_offset_from_local_with_ms(epoch) * 3600)


def local_to_iso(ts: str) -> str:
    return epoch_to_iso(local_to_epoch(ts))


def local_to_local_with_ms(ts: str) -> str:
    # We don't need precision to the nano second. Milliseconds work just fine.
    return epoch_to_local_with_ms(local_to_epoch(ts))[:-3]


def now(offset: float = 0.0, hp: bool = False) -> float:
    epoch = time() + offset

    if hp:
        return epoch

    # Make sure that the float precision does not exceed 6 decimals
    return float(str(epoch)[:17])


def now_as_iso(offset: float = 0.0) -> str:
    return epoch_to_iso(now(offset))


def now_as_local(offset: float = 0.0) -> str:
    return epoch_to_local(now(offset))


def now_as_db(offset: float = 0.0, date_format: str = DB_FMT) -> str:
    return format_time(datetime.fromtimestamp(now(offset)), date_format)


def utc_offset_from_local(cur_time: Optional[float] = None) -> float:
    if not cur_time:
        cur_time = time()
    return int(cur_time - iso_to_epoch("%sZ" % epoch_to_local(cur_time).replace(" ", "T"))) / 3600


def utc_offset_from_local_with_ms(cur_time: Optional[float] = None) -> float:
    if not cur_time:
        cur_time = time()
    return int(cur_time - iso_to_epoch("%sZ" % epoch_to_local_with_ms(cur_time).replace(" ", "T"))) / 3600


def trunc_day(timeobj: datetime) -> datetime:
    """Truncate a datetime object to the nearest day."""
    return timeobj.replace(hour=0, minute=0, second=0, microsecond=0)


def format_time(timeobj: datetime, date_format: Optional[str] = None) -> str:
    """Format a datetime object to the specific iso UTC string the datastore desires, or to a specific date format."""
    # Strip out any existing time zone data, because the time zone formatting
    # isoformat uses by default is offset based, rather than suffex code '+0' vs 'Z'
    timeobj = timeobj.replace(tzinfo=None)

    if not date_format:
        # Put it in a timezone missing iso simulation, then add the zulu 'Z'
        return timeobj.isoformat() + 'Z'
    else:
        return timeobj.strftime(date_format)


def ensure_time_format(ts: str, date_format: str) -> str:
    """
    A nice helper method for checking a time format without having to deal with datetime. Just pass a timestamp string
    and a date format and you'll get the timestamp back if the date format is followed, or an error will be raised.
    """
    try:
        datetime.strptime(ts, date_format)
    except ValueError:
        raise
    return ts
