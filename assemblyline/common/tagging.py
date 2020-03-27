import re

from typing import List, Dict

from assemblyline.common.dict_utils import flatten
from assemblyline.odm.models.tagging import Tagging


def tag_list_to_dict(tag_list: List[Dict]) -> Dict:
    tag_dict = {}
    for t in tag_list:
        if t['type'] not in tag_dict:
            tag_dict[t['type']] = []
        tag_dict[t['type']].append(t['value'])

    return tag_dict


def tag_dict_to_list(tag_dict: Dict) -> List[Dict]:
    return [
        {'type': k, 'value': t, 'short_type': k.rsplit(".", 1)[-1]}
        for k, v in flatten(tag_dict).items()
        if v is not None
        for t in v
    ]


class InvalidWhitelist(Exception):
    pass


class TagWhitelister(object):
    def __init__(self, data, log=None):
        valid_tags = set(Tagging.flat_fields().keys())

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
        return [x for x in t_values if not self.is_whitelisted(t_type, x)]

    def get_validated_tag_map(self, tag_map):
        return {k: self.whitelist_many(k, v) for k, v in tag_map.items() if v is not None}
