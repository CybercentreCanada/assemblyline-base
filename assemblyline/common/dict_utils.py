from collections.abc import Mapping
from typing import AnyStr, Dict, List, Optional, Union
from typing import Mapping as _Mapping

from assemblyline.common.uid import get_id_from_data


def strip_nulls(d):
    if isinstance(d, dict):
        new_dict = {}
        for k, v in list(d.items()):
            v = strip_nulls(v) if v is not None else None
            # Assess if stripped value is null, if not then add it to the new dictionary returned
            if v:
                new_dict[k] = v
        return new_dict
    elif isinstance(d, list):
        return [strip_nulls(v) for v in d if v is not None]
    else:
        return d

def is_equivalent(d1: Dict, d2: Dict):
    equivalent = True
    if isinstance(d1, dict):
        for k, v in d1.items():
            if v and isinstance(v, list):
                if isinstance(v[0], dict):
                    for index, vi in enumerate(v):
                        for vk, vv in vi.items():
                            equivalent |= d2[k][index].get(vk) == vv
            elif isinstance(v, dict):
                equivalent |= is_equivalent(v, d2.get(k))
            else:
                equivalent |= v == d2.get(k)
    else:
        equivalent |= v == d2.get(k)
    return equivalent

def recursive_update(d: Union[Dict, List], u: Union[_Mapping, List],
                        stop_keys: List[AnyStr] = [],
                        list_group_by: Dict[str, str] = {},
                        allow_recursion: bool = True) -> Union[Dict, _Mapping]:

    def _recursive_update(d: Union[Dict, List], u: Union[_Mapping, List],
                        stop_keys: List[AnyStr] = [],
                        allow_recursion: bool = True,
                        context: str = "") -> Union[Dict, _Mapping]:
        if d is None:
            return u

        if u is None:
            return d

        if u == {} and context != "":
            # An empty dict as an update means we want to clear out this dict but this shouldn't apply to the root
            return u

        for k, v in u.items():
            current_context = f"{context}.{k}" if context else k
            if isinstance(v, Mapping) and allow_recursion:
                d[k] = _recursive_update(d.get(k), v, stop_keys=stop_keys, allow_recursion=k not in stop_keys, context=current_context)
            elif isinstance(v, List) and current_context in list_group_by and allow_recursion:
                # We have a list and a key to match on for this key for merging List of Dicts
                d_list = d.get(k, [])
                u_list = v
                key = list_group_by[current_context]

                if u_list == []:
                    # If the update list is empty, we just take it as is (to allow for clearing out lists)
                    d[k] = []
                    continue

                # Create dicts keyed on the specified key for both lists
                d_dict = {str(i[key]): i for i in d_list if key in i}
                u_dict = {str(i[key]): i for i in u_list if key in i}

                merged_list = []
                # Otherwise we merge the lists based on the specified key
                for sub_k, sub_v in u_dict.items():
                    if sub_k in d_dict:
                        merged_list.append(_recursive_update(d_dict[sub_k], sub_v, stop_keys=stop_keys,
                                                        allow_recursion=True,
                                                        context=current_context))
                    else:
                        merged_list.append(sub_v)

                d[k] = merged_list
            else:
                    d[k] = v

        return d
    return _recursive_update(d, u, stop_keys=stop_keys, allow_recursion=allow_recursion)

def get_recursive_delta(d1: Union[Dict, Mapping, List], d2: Union[Dict, Mapping, List],
                        stop_keys: List[AnyStr] = [],
                        list_group_by: Dict[str, str] = {},
                        required_keys: List[AnyStr] = [],
                        allow_recursion: bool = True) -> Dict:
    def _get_recursive_delta(d1: Union[Dict, Mapping, List], d2: Union[Dict, Mapping, List],
                            stop_keys: List[AnyStr] = [],
                            allow_recursion: bool = True,
                            context: str = "") -> Dict:
        if d1 is None:
            return d2

        if d2 is None:
            return d1

        out = {}
        for k1, v1 in d1.items():
            current_context = f"{context}.{k1}" if context else k1
            if isinstance(v1, Mapping) and allow_recursion:
                internal = _get_recursive_delta(v1, d2.get(k1, {}), stop_keys=stop_keys, allow_recursion=k1 not in stop_keys, context=current_context)

                if internal:
                    # We have a delta in this sub-dictionary
                    out[k1] = internal
                elif k1 in d2 and d2[k1] == {}:
                    # Update intended to clear out this dict
                    out[k1] = {}
            elif isinstance(v1, List) and current_context in list_group_by and allow_recursion:
                # We have a list and a key to match on for this context for calculating the delta of List of Dicts
                if k1 in d2 and d2[k1] == []:
                    # Update intended to clear out this list
                    out[k1] = []
                    continue

                v2 = d2.get(k1, [])
                key = list_group_by[current_context]

                # Create dicts keyed on the specified key for both lists
                v1_dict = {str(i[key]): i for i in v1 if key in i}
                v2_dict = {str(i[key]): i for i in v2 if key in i}

                list_out = []
                for sub_k1, sub_v1 in v1_dict.items():
                    if sub_k1 in v2_dict:
                        internal = _get_recursive_delta(sub_v1, v2_dict[sub_k1], stop_keys=stop_keys,
                                                        allow_recursion=True,
                                                        context=current_context)
                        if internal:
                            # We need to preserve the key to know what to match on during merges
                            internal[key] = sub_k1
                            list_out.append(internal)

                for sub_k2, sub_v2 in v2_dict.items():
                    if sub_k2 not in v1_dict:
                        list_out.append(sub_v2)

                if list_out:
                    out[k1] = list_out
            else:
                if k1 in d2:
                    v2 = d2[k1]
                    if v1 != v2:
                        out[k1] = v2

            if current_context in required_keys and k1 not in out and v2 != d2.get(k1):
                # This is a required key, we need to preserve it in the output even if it hasn't changed
                out[k1] = v1


        for k2, v2 in d2.items():
            if k2 not in d1:
                out[k2] = v2

        return out
    return _get_recursive_delta(d1, d2, stop_keys=stop_keys, allow_recursion=allow_recursion)


def get_recursive_sorted_tuples(data: Dict):
    def sort_lists(ldata: List):
        new_list = []
        for i in ldata:
            if isinstance(i, list):
                i = sort_lists(i)
            elif isinstance(i, dict):
                i = get_recursive_sorted_tuples(i)

            new_list.append(i)
        return new_list

    items = []
    for k, v in sorted(data.items()):
        if isinstance(v, dict):
            v = get_recursive_sorted_tuples(v)
        elif isinstance(v, list):
            v = sort_lists(v)

        items.append((k, v))

    return items


def get_dict_fingerprint_hash(data: Dict):
    return get_id_from_data(str(get_recursive_sorted_tuples(data)))


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
