from collections.abc import Mapping
from typing import Dict, Optional, AnyStr, List, Mapping as _Mapping, Union


def strip_nulls(d):
    if isinstance(d, dict):
        return {k: strip_nulls(v) for k, v in d.items() if v is not None and strip_nulls(v)}
    else:
        return d


def recursive_update(d: Dict, u: _Mapping,
                     stop_keys: List[AnyStr] = [],
                     allow_recursion: bool = True) -> Union[Dict, _Mapping]:
    if d is None:
        return u

    if u is None:
        return d

    for k, v in u.items():
        if isinstance(v, Mapping) and allow_recursion:
            d[k] = recursive_update(d.get(k, {}), v, stop_keys=stop_keys, allow_recursion=k not in stop_keys)
        else:
            d[k] = v

    return d


def get_recursive_delta(d1: Union[Dict, Mapping], d2: Union[Dict, Mapping],
                        stop_keys: List[AnyStr] = [],
                        allow_recursion: bool = True) -> Dict:
    if d1 is None:
        return d2

    if d2 is None:
        return d1

    out = {}
    for k1, v1 in d1.items():
        if isinstance(v1, Mapping) and allow_recursion:
            internal = get_recursive_delta(v1, d2.get(k1, {}), stop_keys=stop_keys, allow_recursion=k1 not in stop_keys)
            if internal:
                out[k1] = internal
        else:
            if k1 in d2:
                v2 = d2[k1]
                if v1 != v2:
                    out[k1] = v2

    for k2, v2 in d2.items():
        if k2 not in d1:
            out[k2] = v2

    return out


def flatten(data: Dict, parent_key: Optional[str] = None) -> Dict:
    items = []
    for k, v in data.items():
        cur_key = f"{parent_key}.{k}" if parent_key is not None else k
        if isinstance(v, dict):
            items.extend(flatten(v, cur_key).items())
        else:
            items.append((cur_key, v))

    return dict(items)


def unflatten(data: Dict) -> Dict:
    out = dict()
    for k, v in data.items():
        parts = k.split(".")
        d = out
        for p in parts[:-1]:
            if p not in d:
                d[p] = dict()
            d = d[p]
        d[parts[-1]] = v
    return out
