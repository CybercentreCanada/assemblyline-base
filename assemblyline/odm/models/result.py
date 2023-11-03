from collections import defaultdict
from typing import Any, Dict

from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.caching import generate_conf_key
from assemblyline.common.dict_utils import flatten
from assemblyline.common.str_utils import StringTable
from assemblyline.common.tagging import tag_dict_to_list
from assemblyline.odm.models.tagging import Tagging

BODY_FORMAT = StringTable('BODY_FORMAT', [
    ('TEXT', 0),
    ('MEMORY_DUMP', 1),
    ('GRAPH_DATA', 2),
    ('URL', 3),
    ('JSON', 4),
    ('KEY_VALUE', 5),
    ('PROCESS_TREE', 6),
    ('TABLE', 7),
    ('IMAGE', 8),
    ('MULTI', 9),
    ('DIVIDER', 10),  # This is not a real result section and can only be use inside a multi section
    ('ORDERED_KEY_VALUE', 11),
    ('TIMELINE', 12)
])
PROMOTE_TO = StringTable('PROMOTE_TO', [
    ('SCREENSHOT', 0),
    ('ENTROPY', 1),
    ('URI_PARAMS', 2)
])
PARENT_RELATION = StringTable('PARENT_RELATION', [
    ('ROOT', 0),
    ('EXTRACTED', 1),
    ('INFORMATION', 2),
    ('DYNAMIC', 3),
    ('MEMDUMP', 4),
    ('DOWNLOADED', 5),
])
constants = forge.get_constants()


@odm.model(index=True, store=False)
class Attack(odm.Model):
    attack_id = odm.Keyword(copyto="__text__", description="ID")
    pattern = odm.Keyword(copyto="__text__", description="Pattern Name")
    categories = odm.List(odm.Keyword(), description="Categories")


@odm.model(index=True, store=False, description="Heuristic Signatures")
class Signature(odm.Model):
    name = odm.Keyword(copyto="__text__", description="Name of the signature that triggered the heuristic")
    frequency = odm.Integer(default=1, description="Number of times this signature triggered the heuristic")
    safe = odm.Boolean(default=False, description="Is the signature safelisted or not")


@odm.model(index=True, store=False, description="Heuristic associated to the Section")
class Heuristic(odm.Model):
    heur_id = odm.Keyword(copyto="__text__", description="ID of the heuristic triggered")
    name = odm.Keyword(copyto="__text__", description="Name of the heuristic")
    attack = odm.List(odm.Compound(Attack), default=[], description="List of Att&ck IDs related to this heuristic")
    signature = odm.List(odm.Compound(Signature), default=[],
                         description="List of signatures that triggered the heuristic")
    score = odm.Integer(description="Calculated Heuristic score")


@odm.model(index=True, store=False, description="Result Section")
class Section(odm.Model):
    auto_collapse = odm.Boolean(default=False, description="Should the section be collapsed when displayed?")
    body = odm.Optional(odm.Text(copyto="__text__"), description="Text body of the result section")
    classification = odm.Classification(description="Classification of the section")
    body_format = odm.Enum(values=set(BODY_FORMAT._value_map.keys()), index=False, description="Type of body in this section")
    body_config = odm.Optional(odm.Mapping(odm.Any(), index=False,
                               description="Configurations for the body of this section"))
    depth = odm.Integer(index=False, description="Depth of the section")
    heuristic = odm.Optional(odm.Compound(Heuristic), description="Heuristic used to score result section")
    tags = odm.Compound(Tagging, default={}, description="List of tags associated to this section")
    safelisted_tags = odm.FlattenedListObject(store=False, default={}, description="List of safelisted tags")
    title_text = odm.Text(copyto="__text__", description="Title of the section")
    promote_to = odm.Optional(odm.Enum(
        values=set(PROMOTE_TO._value_map.keys()),
        description="This is the type of data that the current section should be promoted to."))


@odm.model(index=True, store=True, description="Result Body")
class ResultBody(odm.Model):
    score = odm.Integer(default=0, description="Aggregate of the score for all heuristics")
    sections = odm.List(odm.Compound(Section), default=[], description="List of sections")


@odm.model(index=False, store=False, description="Service Milestones")
class Milestone(odm.Model):
    service_started = odm.Date(default="NOW", description="Date the service started scanning")
    service_completed = odm.Date(default="NOW", description="Date the service finished scanning")


@odm.model(index=True, store=False, description="File related to the Response")
class File(odm.Model):
    name = odm.Keyword(copyto="__text__", description="Name of the file")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 of the file")
    description = odm.Text(copyto="__text__", description="Description of the file")
    classification = odm.Classification(description="Classification of the file")
    is_section_image = odm.Boolean(default=False,
                                   description="Is this an image used in an Image Result Section?")
    parent_relation = odm.Enum(
        values=set(PARENT_RELATION._value_map.keys()),
        index=False,
        description="File relation to parent, if any."
    )
    allow_dynamic_recursion = odm.Boolean(
        default=False,
        description="Allow file to be analysed during Dynamic Analysis"
                    "even if Dynamic Recursion Prevention is enabled.")


@odm.model(index=True, store=True, description="Response Body of Result")
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone, default={}, description="Milestone block")
    service_version = odm.Keyword(store=False, description="Version of the service")
    service_name = odm.Keyword(copyto="__text__", description="Name of the service that scanned the file")
    service_tool_version = odm.Optional(odm.Keyword(copyto="__text__"), description="Tool version of the service")
    supplementary = odm.List(odm.Compound(File), default=[], description="List of supplementary files")
    extracted = odm.List(odm.Compound(File), default=[], description="List of extracted files")
    service_context = odm.Optional(odm.Keyword(index=False, store=False), description="Context about the service")
    service_debug_info = odm.Optional(odm.Keyword(index=False, store=False), description="Debug info about the service")


@odm.model(index=True, store=True, description="Result Model")
class Result(odm.Model):
    archive_ts = odm.Optional(odm.Date(store=False, description="Archiving timestamp (Deprecated)"))
    classification = odm.Classification(description="Aggregate classification for the result")
    created = odm.Date(default="NOW", description="Date at which the result object got created")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")
    response: ResponseBody = odm.compound(ResponseBody, description="The body of the response from the service")
    result: ResultBody = odm.compound(ResultBody, default={}, description="The result body")
    sha256 = odm.SHA256(store=False, description="SHA256 of the file the result object relates to")
    type = odm.Optional(odm.Keyword())
    size = odm.Optional(odm.Integer())
    drop_file = odm.Boolean(default=False, description="Use to not pass to other stages after this run")
    from_archive = odm.Boolean(index=False, default=False, description="Was loaded from the archive")

    def build_key(self, service_tool_version=None, task=None):
        return self.help_build_key(
            self.sha256,
            self.response.service_name,
            self.response.service_version,
            self.is_empty(),
            service_tool_version=service_tool_version,
            task=task
        )

    @staticmethod
    def help_build_key(sha256, service_name, service_version, is_empty, service_tool_version=None, task=None):
        key_list = [
            sha256,
            service_name.replace('.', '_'),
            f"v{service_version.replace('.', '_')}",
            f"c{generate_conf_key(service_tool_version=service_tool_version, task=task)}",
        ]

        if is_empty:
            key_list.append("e")

        return '.'.join(key_list)

    def scored_tag_dict(self) -> Dict[str, Dict[str, Any]]:
        tags: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'score': 0})
        # Save the tags and their score
        for section in self.result.sections:
            tag_list = tag_dict_to_list(flatten(section.tags.as_primitives()))
            for tag in tag_list:
                key = f"{tag['type']}:{tag['value']}"
                tags[key].update(tag)
                tags[key]['score'] += section.heuristic.score if section.heuristic else 0

        return tags

    def is_empty(self) -> bool:
        if len(self.response.extracted) == 0 and \
                len(self.response.supplementary) == 0 and \
                len(self.result.sections) == 0 and \
                self.result.score == 0:
            return True
        return False
