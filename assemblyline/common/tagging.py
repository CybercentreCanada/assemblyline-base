import re

from typing import List, Dict, Set

from assemblyline.common.forge import CachedObject, get_datastore
from assemblyline.odm.models.tagging import Tagging


def tag_list_to_dict(tag_list: List[Dict]) -> Dict:
    tag_dict = {}
    for t in tag_list:
        if t['type'] not in tag_dict:
            tag_dict[t['type']] = []
        tag_dict[t['type']].append(t['value'])

    return tag_dict


def tag_dict_to_list(tag_dict: Dict, safelisted: bool = False) -> List[Dict]:
    return [
        {'safelisted': safelisted, 'type': k, 'value': t, 'short_type': k.rsplit(".", 1)[-1]}
        for k, v in tag_dict.items()
        if v is not None
        for t in v
    ]


def get_safelist_key(t_type: str, t_value: str) -> str:
    return f"{t_type}__{t_value}"


def get_safelist(ds) -> Set:
    return {get_safelist_key(sl['tag']['type'], sl['tag']['value']): True
            for sl in ds.safelist.stream_search("type:tag AND enabled:true", as_obj=False)}


class InvalidWhitelist(Exception):
    pass


class TagWhitelister(object):
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
                raise InvalidWhitelist(f"Section {section} should be of type: DICT")

            for k, v in item.items():
                if not isinstance(v, list):
                    raise InvalidWhitelist(f"Values in the {section} section should all be of type: LIST")

                if k not in valid_tags:
                    raise InvalidWhitelist(f"Key ({k}) in the {section} section is not a valid tag.")

                if section == 'regex':
                    self.regex[k] = [re.compile(x) for x in v]

    def is_whitelisted(self, t_type, t_value):
        if self.safelist.get(get_safelist_key(t_type, t_value), False):
            if self.log:
                self.log.info(f"Tag '{t_type}' with value '{t_value}' was safelisted.")
            return True

        for match in self.match.get(t_type, []):
            if t_value == match:
                if self.log:
                    self.log.info(f"Tag '{t_type}' with value '{t_value}' was whitelisted by match rule.")
                return True

        for regex in self.regex.get(t_type, []):
            if regex.match(t_value):
                if self.log:
                    self.log.info(f"Tag '{t_type}' with value '{t_value}' "
                                  f"was whitelisted by regex '{regex.pattern}'.")
                return True

        return False

    def whitelist_many(self, t_type, t_values):
        if not isinstance(t_values, list):
            t_values = [t_values]

        tags = []
        safelisted_tags = []
        for x in t_values:
            if self.is_whitelisted(t_type, x):
                safelisted_tags.append(x)
            else:
                tags.append(x)

        return tags, safelisted_tags

    def get_validated_tag_map(self, tag_map):
        tags = {}
        safelisted_tags = {}
        for k, v in tag_map.items():
            if v is not None and v != []:
                c_tags, c_safelisted_tags = self.whitelist_many(k, v)
                if c_tags:
                    tags[k] = c_tags
                if c_safelisted_tags:
                    safelisted_tags[k] = c_safelisted_tags

        return tags, safelisted_tags
