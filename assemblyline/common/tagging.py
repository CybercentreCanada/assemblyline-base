from typing import List, Dict

from assemblyline.common.dict_utils import flatten


def tag_list_to_dict(tag_list: List) -> Dict:
    tag_dict = {}
    for t in tag_list:
        if t['type'] not in tag_dict:
            tag_dict[t['type']] = []
        tag_dict[t['type']].append(t['value'])

    return tag_dict


def tag_dict_to_list(tag_dict: Dict) -> List:
    return [
        {'type': k,
         'value': t,
         'short_type': k.rsplit(".", 1)[-1]}
        for k, v in flatten(tag_dict).items()
        if v is not None
        for t in v
    ]
