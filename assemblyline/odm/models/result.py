from collections import defaultdict
from typing import Any, Dict

from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.caching import generate_conf_key
from assemblyline.common.dict_utils import flatten
from assemblyline.common.tagging import tag_dict_to_list
from assemblyline.odm.models.tagging import Tagging

# This is a "keys-only" representation of the BODY_FORMAT StringTable in
# assemblyline-v4-service/assemblyline_v4_service/common/result.py.
# Any updates here need to go in that StringTable also.
BODY_FORMAT = {
    "TEXT",
    "MEMORY_DUMP",
    "GRAPH_DATA",
    "URL",
    "JSON",
    "KEY_VALUE",
    "PROCESS_TREE",
    "TABLE",
    "IMAGE",
    "MULTI",
    "ORDERED_KEY_VALUE",
    "TIMELINE"
}
# This is a "keys-only" representation of the PROMOTE_TO StringTable in
# assemblyline-v4-service/assemblyline_v4_service/common/result.py.
# Any updates here need to go in that StringTable also.
PROMOTE_TO = {"SCREENSHOT", "ENTROPY", "URI_PARAMS"}
constants = forge.get_constants()


@odm.model(index=True, store=False)
class Attack(odm.Model):
    attack_id = odm.Keyword(copyto="__text__", description="ID", ai=False)
    pattern = odm.Keyword(copyto="__text__", description="Pattern Name")
    categories = odm.List(odm.Keyword(), description="Categories")


@odm.model(index=True, store=False, description="Heuristic Signatures")
class Signature(odm.Model):
    name = odm.Keyword(copyto="__text__", description="Name of the signature that triggered the heuristic")
    frequency = odm.Integer(default=1, description="Number of times this signature triggered the heuristic")
    safe = odm.Boolean(default=False, description="Is the signature safelisted or not")


@odm.model(index=True, store=False, description="Heuristic associated to the Section")
class Heuristic(odm.Model):
    heur_id = odm.Keyword(copyto="__text__", description="ID of the heuristic triggered", ai=False)
    name = odm.Keyword(copyto="__text__", description="Name of the heuristic")
    attack = odm.List(odm.Compound(Attack), default=[], description="List of Att&ck IDs related to this heuristic")
    signature = odm.List(odm.Compound(Signature), default=[],
                         description="List of signatures that triggered the heuristic", ai=False)
    score = odm.Integer(description="Calculated Heuristic score")


@odm.model(index=True, store=False, description="Result Section")
class Section(odm.Model):
    auto_collapse = odm.Boolean(default=False, description="Should the section be collapsed when displayed?", ai=False)
    body = odm.Optional(odm.Text(copyto="__text__"), description="Text body of the result section")
    classification = odm.Classification(description="Classification of the section", ai=False)
    body_format = odm.Enum(values=BODY_FORMAT, index=False, description="Type of body in this section")
    body_config = odm.Optional(odm.Mapping(odm.Any(), index=False,
                               description="Configurations for the body of this section"), ai=False)
    depth = odm.Integer(index=False, description="Depth of the section", ai=False)
    heuristic = odm.Optional(odm.Compound(Heuristic), description="Heuristic used to score result section")
    tags = odm.Compound(Tagging, default={}, description="List of tags associated to this section")
    safelisted_tags = odm.FlattenedListObject(store=False, default={}, description="List of safelisted tags", ai=False)
    title_text = odm.Text(copyto="__text__", description="Title of the section")
    promote_to = odm.Optional(odm.Enum(
        values=PROMOTE_TO,
        description="This is the type of data that the current section should be promoted to.", ai=False))


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
    classification = odm.Classification(description="Classification of the file", ai=False)
    is_section_image = odm.Boolean(default=False,
                                   description="Is this an image used in an Image Result Section?", ai=False)
    # Possible values for PARENT_RELATION can be found in
    # assemblyline-v4-service/assemblyline_v4_service/common/task.py.
    parent_relation = odm.Text(
        default="EXTRACTED",
        description="File relation to parent, if any.\
            <br>Values: `\"ROOT\", \"EXTRACTED\", \"INFORMATION\", \"DYNAMIC\", \"MEMDUMP\", \"DOWNLOADED\"`", ai=False
    )
    allow_dynamic_recursion = odm.Boolean(
        default=False,
        description="Allow file to be analysed during Dynamic Analysis"
                    "even if Dynamic Recursion Prevention is enabled.", ai=False)


@odm.model(index=True, store=True, description="Response Body of Result")
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone, default={}, description="Milestone block", ai=False)
    service_version = odm.Keyword(store=False, description="Version of the service", ai=False)
    service_name = odm.Keyword(copyto="__text__", description="Name of the service that scanned the file")
    service_tool_version = odm.Optional(
        odm.Keyword(copyto="__text__"),
        description="Tool version of the service", ai=False)
    supplementary = odm.List(odm.Compound(File), default=[], description="List of supplementary files", ai=False)
    extracted = odm.List(odm.Compound(File), default=[], description="List of extracted files")
    service_context = odm.Optional(
        odm.Keyword(index=False, store=False),
        description="Context about the service", ai=False)
    service_debug_info = odm.Optional(
        odm.Keyword(index=False, store=False),
        description="Debug info about the service", ai=False)


@odm.model(index=True, store=True, description="Result Model")
class Result(odm.Model):
    archive_ts = odm.Optional(odm.Date(store=False, description="Archiving timestamp (Deprecated)", ai=False))
    classification = odm.Classification(description="Aggregate classification for the result", ai=False)
    created = odm.Date(default="NOW", description="Date at which the result object got created", ai=False)
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp", ai=False)
    response: ResponseBody = odm.compound(ResponseBody, description="The body of the response from the service")
    result: ResultBody = odm.compound(ResultBody, default={}, description="The result body")
    sha256 = odm.SHA256(store=False, description="SHA256 of the file the result object relates to")
    type = odm.Optional(odm.Keyword())
    size = odm.Optional(odm.Integer())
    drop_file = odm.Boolean(default=False, description="Use to not pass to other stages after this run", ai=False)
    from_archive = odm.Boolean(index=False, default=False, description="Was loaded from the archive", ai=False)

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
