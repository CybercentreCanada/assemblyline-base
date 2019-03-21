import collections

def recursive_update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = recursive_update(d.get(k, {}), v)
        else:
            d[k] = v

    return d


def get_recursive_delta(d1, d2):
    out = {}
    for k1, v1 in d1.items():
        if isinstance(v1, collections.Mapping):
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
