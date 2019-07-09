import collections

def recursive_update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = recursive_update(d.get(k, {}), v)
        else:
            d[k] = v

    return d


def get_recursive_delta(d1, d2):
    out = {}
    for k1, v1 in d1.items():
        if isinstance(v1, collections.abc.Mapping):
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


def flatten(data, parent_key=None):
    items = []
    for k, v in data.items():
        cur_key = f"{parent_key}.{k}" if parent_key is not None else k
        if isinstance(v, dict):
            items.extend(flatten(v, cur_key).items())
        else:
            items.append((cur_key, v))

    return dict(items)


def unflatten(data):
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
