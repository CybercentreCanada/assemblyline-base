from __future__ import annotations


def tag_list_to_dict(tag_list: list[dict]) -> dict:
    tag_dict = {}
    for t in tag_list:
        if t['type'] not in tag_dict:
            tag_dict[t['type']] = []
        tag_dict[t['type']].append(t['value'])

    return tag_dict


def tag_dict_to_list(tag_dict: dict, safelisted: bool = False) -> list[dict]:
    return [
        {'safelisted': safelisted, 'type': k, 'value': t, 'short_type': k.rsplit(".", 1)[-1]}
        for k, v in tag_dict.items()
        if v is not None
        for t in v
    ]


def tag_dict_to_ai_list(tag_dict: dict) -> list[dict]:
    return [
        {'type': k, 'value': t}
        for k, v in tag_dict.items()
        if v is not None
        for t in v
    ]


def get_safelist_key(t_type: str, t_value: str) -> str:
    return f"{t_type}__{t_value}"


def get_safelist(ds) -> dict[str, bool]:
    return {get_safelist_key(sl['tag']['type'], sl['tag']['value']): True
            for sl in ds.safelist.stream_search("type:tag AND enabled:true", as_obj=False)}


