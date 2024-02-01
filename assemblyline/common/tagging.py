from __future__ import annotations
import re

from assemblyline.common.forge import CachedObject, get_datastore
from assemblyline.odm.models.tagging import Tagging


def tag_list_to_dict(tag_list: list[dict]) -> dict:
    tag_dict = {}
    for t in tag_list:
        if t['type'] not in tag_dict:
            tag_dict[t['type']] = []
        tag_dict[t['type']].append(t['value'])

    return tag_dict


def tag_dict_to_list(tag_dict: dict, safelisted: bool = False, ai: bool = False) -> list[dict]:
    if ai:
        return [
            {'type': k, 'value': t}
            for k, v in tag_dict.items()
            if v is not None
            for t in v
        ]
    else:
        return [
            {'safelisted': safelisted, 'type': k, 'value': t, 'short_type': k.rsplit(".", 1)[-1]}
            for k, v in tag_dict.items()
            if v is not None
            for t in v
        ]


def get_safelist_key(t_type: str, t_value: str) -> str:
    return f"{t_type}__{t_value}"


def get_safelist(ds) -> dict[str, bool]:
    return {get_safelist_key(sl['tag']['type'], sl['tag']['value']): True
            for sl in ds.safelist.stream_search("type:tag AND enabled:true", as_obj=False)}


class InvalidSafelist(Exception):
    pass


class TagSafelister(object):
    def __init__(self, data, log=None):
        valid_tags = set(Tagging.flat_fields().keys())
        self.datastore = get_datastore()
        self.safelist = CachedObject(get_safelist, kwargs={'ds': self.datastore}, refresh=300)

        self.match = data.get('match', {})
        self.regex = data.get('regex', {})
        self.log = log

        # Validate matches and regex
        for section, item in {'match': self.match, 'regex': self.regex}.items():
            if not isinstance(item, dict):
                raise InvalidSafelist(f"Section {section} should be of type: DICT")

            for k, v in item.items():
                if not isinstance(v, list):
                    raise InvalidSafelist(f"Values in the {section} section should all be of type: LIST")

                if k not in valid_tags:
                    raise InvalidSafelist(f"Key ({k}) in the {section} section is not a valid tag.")

                if section == 'regex':
                    self.regex[k] = [re.compile(x) for x in v]

    def is_safelisted(self, t_type, t_value):
        if self.safelist.get(get_safelist_key(t_type, t_value), False):
            if self.log:
                self.log.info(f"Tag '{t_type}' with value '{t_value}' was safelisted.")
            return True

        for match in self.match.get(t_type, []):
            if t_value == match:
                if self.log:
                    self.log.info(f"Tag '{t_type}' with value '{t_value}' was safelisted by match rule.")
                return True

        for regex in self.regex.get(t_type, []):
            if regex.match(t_value):
                if self.log:
                    self.log.info(f"Tag '{t_type}' with value '{t_value}' "
                                  f"was safelisted by regex '{regex.pattern}'.")
                return True

        return False

    def safelist_many(self, t_type, t_values):
        if not isinstance(t_values, list):
            t_values = [t_values]

        tags = []
        safelisted_tags = []
        for x in t_values:
            if self.is_safelisted(t_type, x):
                safelisted_tags.append(x)
            else:
                tags.append(x)

        return tags, safelisted_tags

    def get_validated_tag_map(self, tag_map):
        tags = {}
        safelisted_tags = {}
        for k, v in tag_map.items():
            if v is not None and v != []:
                c_tags, c_safelisted_tags = self.safelist_many(k, v)
                if c_tags:
                    tags[k] = c_tags
                if c_safelisted_tags:
                    safelisted_tags[k] = c_safelisted_tags

        return tags, safelisted_tags
