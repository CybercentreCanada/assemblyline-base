import logging
import os
import re
import yara

from collections import defaultdict
from typing import Tuple, Union, Dict

from assemblyline.common.forge import get_constants
from assemblyline.common.str_utils import safe_str

LOGGER = logging.getLogger('assemblyline.identify')

STRONG_INDICATORS = {
    "code/perl": [
        re.compile(rb"(^|\n)[ \t]*my[ \t]+\$\w+[ \t]*="),
        re.compile(rb"(^|\n)[ \t]*sub[ \t]+\w+[ \t]*{"),
    ],
    "code/ruby": [
        re.compile(rb"(^|\n)[ \t]*require(_all)?[ \t]*\'[\w/]+\'"),
        re.compile(rb"rescue[ \t]+\w+[ \t]+=>"),
    ],
    "code/go": [
        re.compile(rb"(^|\n)[ \t]*import[ \t]+\("),
        re.compile(rb"(^|\n)[ \t]*func[ \t]+\w+\("),
    ],
    "code/css": [
        re.compile(
            rb"(^|\n|\})(html|body|footer|span\.|img\.|a\.|\.[a-zA-Z\-.]+)[^{]+{"
            rb"[ \t]*(padding|color|width|margin|background|font|text)[^}]+\}"
        ),
    ],
    "text/markdown": [
        re.compile(rb"\*[ \t]*`[^`]+`[ \t]*-[ \t]*\w+"),
    ],
    "metadata/sysmon": [
        re.compile(rb"<Events>[^>]+"),
        re.compile(rb"<Event>[^>]+"),
        re.compile(rb"<\/Event>"),
        re.compile(rb"<\/Events>"),
    ],
    "code/xml": [
        # Check if it has an xml declaration header
        re.compile(rb"^\s*<\?xml[^>]+\?>", re.DOTALL | re.MULTILINE),
        # Check if it begins and ends with <tag ... and </tag ...> (for informal xml usages)
        re.compile(rb"^\s*<(?P<open>[\w:]+).+</(?P=open)>\s*$", re.DOTALL),
        # Check if a tag has an xmlns attribute
        re.compile(rb"<[^>]+xmlns[:=][^>]+>", re.MULTILINE),
    ],
    "code/postscript": [
        re.compile(rb"%!PS"),
        re.compile(rb"def /\w+"),
    ],
    "code/batch": [
        re.compile(rb"(?i)(^|\n| |\t|@)(chcp|set /p)[ \t]+"),
        re.compile(
            rb"(?i)(^|\n| |\t|&)start[ \t]*/(min|b)[ \t]+.*([ \t]+(-win[ \t]+1[ \t]+)?-enc[ \t]+)?"
        ),
        re.compile(rb"(?i)(^|\n| |\t|&)start[ \t]*/wait[ \t]+.*?"),
        re.compile(rb'(?i)(^|\n|@)cd[ \t]+(/d )?["\']%~dp0["\']'),
        re.compile(rb"(?i)(^|\n)taskkill[ \t]+(/F|/im)"),
        re.compile(rb"(?i)(^|\n)reg[ \t]+delete[ \t]+"),
        re.compile(rb"(?i)(^|\n)%comspec%[ \t]+/c[ \t]+"),
        re.compile(rb"(?i)(^|\n)dir&echo[ \t]+"),
        re.compile(
            rb"(?i)(^|\n)net[ \t]+(share|stop|start|accounts|computer|config|continue|"
            rb"file|group|localgroup|pause|session|statistics|time|use|user|view)"
        ),
    ],
}
STRONG_SCORE = 15
MINIMUM_GUESS_SCORE = 20

WEAK_INDICATORS = {
    "code/sql": [rb"(^|\n)(create|drop|select|returns|declare)[ \t]+"],
    "code/perl": [rb"(^|\n)[ \t]*package[ \t]+[\w\.]+;", b"@_"],
    "text/markdown": [rb"\[[\w]+\]:[ \t]*http:"],
    "code/postscript": [
        rb"pop ",
        rb"\}for ",
        rb"dup ",
        rb"get ",
        rb"xor ",
        rb"copy ",
    ],
    "code/batch": [
        rb"(?i)(^|\n| |\t|@|&)(echo|netsh|sc|pkgmgr|netstat|rem|::|move)[ \t]+",
        rb"(^|\n)pause",
        rb"(^|\n)shutdown[ \t]*(/s)?",
        rb"Set[ \t]+\w+[ \t]*=",
    ],
}
WEAK_SCORE = 1

WEAK_INDICATORS = {k: re.compile(b"|".join(v)) for k, v in WEAK_INDICATORS.items()}

SHEBANG = re.compile(rb"^#![\w./]+/(?:env[ \t]*)?(\w+)[ \t]*\n")

EXECUTABLES = {
    "escript": "erlang",
    "nush": "nu",
    "macruby": "ruby",
    "jruby": "ruby",
    "rbx": "ruby",
}


def _confidence(score: Union[int, float]) -> str:
    conf = float(score) / float(STRONG_SCORE * 5)
    conf = min(1.0, conf) * 100
    return str(int(conf)) + r"%"


def _differentiate(lang: str, scores_map: Dict) -> str:
    if lang == "code/javascript":
        jscript_score = scores_map["code/jscript"]
        pdfjs_score = scores_map["code/pdfjs"]
        if pdfjs_score > 0 and pdfjs_score > jscript_score:
            return "code/pdfjs"
        elif jscript_score > 0:
            return "code/jscript"

    return lang


# Pass a filepath and this will return the guessed language in the AL tag format.
def guess_language_old(path: str, info: Dict, fallback="unknown") -> Tuple[str, Union[str, int]]:
    file_length = os.path.getsize(path)
    with open(path, "rb") as fh:
        if file_length > 131070:
            buf = fh.read(65535)
            fh.seek(file_length - 65535)
            buf += fh.read(65535)
        else:
            buf = fh.read()

    scores = defaultdict(int)
    shebang_lang = re.match(SHEBANG, buf)
    if shebang_lang:
        lang = shebang_lang.group(1)
        lang = "code/" + EXECUTABLES.get(safe_str(lang), safe_str(lang))
        scores[lang] = STRONG_SCORE * 3

    for lang, patterns in STRONG_INDICATORS.items():
        for pattern in patterns:
            for _ in re.findall(pattern, buf):
                scores[lang] += STRONG_SCORE

    for lang, pattern in WEAK_INDICATORS.items():
        for _ in re.findall(pattern, buf):
            scores[lang] += WEAK_SCORE

    for lang in list(scores.keys()):
        if scores[lang] < MINIMUM_GUESS_SCORE:
            scores.pop(lang)

    max_v = 0
    if len(scores) > 0:
        max_v = max(list(scores.values()))
    high_scores = [(k, v) for k, v in scores.items() if v == max_v]
    high_scores = [(_differentiate(k, scores), v) for k, v in high_scores]

    if len(high_scores) != 1:
        return fallback
    else:
        confidences = [(k, _confidence(v)) for k, v in high_scores]
        return confidences[0][0]


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
