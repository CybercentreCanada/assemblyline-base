import logging
import yara

from typing import Tuple, Union, Dict

from assemblyline.common.forge import get_constants

LOGGER = logging.getLogger('assemblyline.identify')

constants = get_constants()
default_externals = {'mime': '', 'magic': '', 'type': ''}
rules_list = {"default": constants.YARA_RULE_PATH}
rules = yara.compile(filepaths=rules_list, externals=default_externals)


def guess_language(path: str, info: Dict, fallback="unknown") -> Tuple[str, Union[str, int]]:
    externals = {k: v or "" for k, v in info.items() if k in default_externals}
    try:
        matches = rules.match(path, externals=externals, fast=True)
        matches.sort(key=lambda x: x.meta.get('score', 0), reverse=True)
        for match in matches:
            return match.meta['type']
    except Exception as e:
        LOGGER.warning(f"Yara file identifier failed with error: {str(e)}")
        matches = []

    return fallback
