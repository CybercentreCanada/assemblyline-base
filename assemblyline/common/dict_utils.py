from collections.abc import Mapping
from typing import Dict, Optional, Mapping as _Mapping, Union


def recursive_update(d: Dict, u: _Mapping) -> Union[Dict, _Mapping]:
    if d is None:
        return u

    if u is None:
        return d

    for k, v in u.items():
        if isinstance(v, Mapping):
            d[k] = recursive_update(d.get(k, {}), v)
        else:
            d[k] = v

    return d


def get_recursive_delta(d1: Union[Dict, Mapping], d2: Union[Dict, Mapping]) -> Dict:
    if d1 is None:
        return d2

    if d2 is None:
        return d1

    out = {}
    for k1, v1 in d1.items():
        if isinstance(v1, Mapping):
            internal = get_recursive_delta(v1, d2.get(k1, {}))
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
