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


@odm.model(index=True, store=False, description="Represents cyber attack tactics or techniques as identified by the MITRE ATT&CK framework.")
class Attack(odm.Model):
    attack_id = odm.Keyword(copyto="__text__", description="Unique identifier corresponding to a specific tactic or technique in the MITRE ATT&CK framework.", ai=False)
    pattern = odm.Keyword(copyto="__text__", description="The name of the MITRE ATT&CK pattern that is associated with the detected malware or malicious activity.")
    categories = odm.List(odm.Keyword(), description="A list of categories that describe and classify the nature of the cyber attack based on the MITRE ATT&CK framework.")


@odm.model(index=True, store=False, description="Describes a signature that has matched, indicating potential malicious behavior.")
class Signature(odm.Model):
    name = odm.Keyword(copyto="__text__", description="Name of the detection signature that triggered the heuristic.")
    frequency = odm.Integer(default=1, description="The count of how many times this particular signature has triggered the heuristic during analysis.")
    safe = odm.Boolean(default=False, description="A boolean indicating whether the signature is considered safe and has been safelisted, thus not contributing to the score.")


@odm.model(index=True, store=False, description="Heuristic associated to the Section")
class Heuristic(odm.Model):
    heur_id = odm.Keyword(copyto="__text__", description="Unique identifier of the heuristic that was triggered, contributing to the overall assessment of potential maliciousness.", ai=False)
    name = odm.Keyword(copyto="__text__", description="The name of the heuristic rule that was triggered during the analysis.")
    attack = odm.List(odm.Compound(Attack), default=[], description="A list of MITRE ATT&CK identifiers that are associated with this heuristic, linking detected behavior to known techniques.")
    signature = odm.List(odm.Compound(Signature), default=[],
                         description="A list of signatures whose detection has contributed to the triggering of this heuristic.", ai=False)
    score = odm.Integer(description="The score assigned by this heuristic, which contributes to the overall threat assessment of the analyzed artifact.")


@odm.model(index=True, store=False, description="Result Section")
class Section(odm.Model):
    auto_collapse = odm.Boolean(default=False, description="Indicates whether the section should be initially displayed as collapsed in the user interface.", ai=False)
    body = odm.Optional(odm.Text(copyto="__text__"), description="The main content of the result section, which may include detailed analysis findings or descriptions.")
    classification = odm.Classification(description="The classification level assigned to the information within the section, dictating who can view it.", ai=False)
    body_format = odm.Enum(values=BODY_FORMAT, index=False, description="The format of the body content, such as text, JSON, or image, which determines how it is displayed.")
    body_config = odm.Optional(odm.Mapping(odm.Any(), index=False),
                               description="Additional configurations that specify how the body content should be rendered or processed.", ai=False)
    depth = odm.Integer(index=False, description="The nesting level of the section within the overall result hierarchy, used for organizing complex results.", ai=False)
    heuristic = odm.Optional(odm.Compound(Heuristic), description="The heuristic analysis that contributed to the scoring of this section, if applicable.")
    tags = odm.Compound(Tagging, default={}, description="A collection of tags that categorize or label the section based on the analysis findings.")
    safelisted_tags = odm.FlattenedListObject(store=False, default={}, description="Tags that have been deemed safe and are excluded from contributing to the overall threat score.", ai=False)
    title_text = odm.Text(copyto="__text__", description="The title of the section, summarizing its content or purpose.")
    promote_to = odm.Optional(odm.Enum(
        values=PROMOTE_TO, ai=False), description="The category of data that this section's content should be elevated to for reporting or further analysis.")


@odm.model(index=True, store=True, description="Result Body")
class ResultBody(odm.Model):
    score = odm.Integer(default=0, description="The total score calculated from all heuristics applied, indicating overall severity.")
    sections = odm.List(odm.Compound(Section), default=[], description="An ordered list of Section objects that detail the analysis results.")


@odm.model(index=False, store=False, description="Service Milestones")
class Milestone(odm.Model):
    service_started = odm.Date(default="NOW", description="Timestamp marking when the service began its analysis of the artifact.")
    service_completed = odm.Date(default="NOW", description="Timestamp marking when the service completed its analysis, signaling the end of processing for the artifact.")


@odm.model(index=True, store=False, description="File related to the Response")
class File(odm.Model):
    name = odm.Keyword(copyto="__text__", description="The original name of the file being analyzed or generated during the analysis process.")
    sha256 = odm.SHA256(copyto="__text__", description="The SHA256 hash of the file, serving as a unique identifier for the content.")
    description = odm.Text(copyto="__text__", description="A brief description of the file's purpose or contents, especially if it is an output of the analysis.")
    classification = odm.Classification(description="The classification level of the file, indicating the sensitivity of its contents.", ai=False)
    is_section_image = odm.Boolean(default=False,
                                   description="A flag indicating whether the file is an image that is used within an image-based result section.", ai=False)
    # Possible values for PARENT_RELATION can be found in
    # assemblyline-v4-service/assemblyline_v4_service/common/task.py.
    parent_relation = odm.Text(
        default="EXTRACTED",
        description="Describes the relationship of this file to the parent file, such as `EXTRACTED` or `DOWNLOADED`.", ai=False
    )
    allow_dynamic_recursion = odm.Boolean(
        default=False,
        description="Specifies whether the file can be analyzed during dynamic analysis, even with recursion prevention.", ai=False)


@odm.model(index=True, store=True, description="Response Body of Result")
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone, default={}, description="A set of key timestamps that mark important stages in the service's processing of the file.", ai=False)
    service_version = odm.Keyword(store=False, description="The version of the service that performed the analysis, important for tracking analysis provenance.", ai=False)
    service_name = odm.Keyword(copyto="__text__", description="The name of the service that conducted the analysis, useful for identifying the source of the results.")
    service_tool_version = odm.Optional(
        odm.Keyword(copyto="__text__"),
        description="The specific version of the analytical tool used by the service, if applicable.", ai=False)
    supplementary = odm.List(odm.Compound(File), default=[], description="A list of additional files generated during analysis that support the main findings.", ai=False)
    extracted = odm.List(odm.Compound(File), default=[], description="A list of files that were extracted from the analyzed artifact during the service's processing.")
    service_context = odm.Optional(
        odm.Keyword(index=False, store=False),
        description="Additional context or metadata about the service's execution environment or configuration.", ai=False)
    service_debug_info = odm.Optional(
        odm.Keyword(index=False, store=False),
        description="Information that can be used for debugging or understanding the service's analysis process.", ai=False)


@odm.model(index=True, store=True, description="Result Model")
class Result(odm.Model):
    archive_ts = odm.Optional(odm.Date(ai=False), description="The timestamp when the result was moved to long-term storage or archived.")
    classification = odm.Classification(description="The highest classification level assigned to any part of the result, dictating overall access control.", ai=False)
    created = odm.Date(default="NOW", description="The creation timestamp for the result record, marking when the analysis result was first generated.", ai=False)
    expiry_ts = odm.Optional(odm.Date(store=False), description="The timestamp when the result is scheduled to be purged or deleted from the system.", ai=False)
    response: ResponseBody = odm.compound(ResponseBody, description="The container for all the response data provided by the service after analyzing the file.")
    result: ResultBody = odm.compound(ResultBody, default={}, description="The container for the detailed results of the analysis, including sections and scores.")
    sha256 = odm.SHA256(store=False, description="The SHA256 hash of the file that was analyzed, linking the result to the specific artifact.")
    type = odm.Optional(odm.Keyword(), description="The MIME type or other file classification identified by Assemblyline that is linked to the result, providing insight into the file's content or format.")
    size = odm.Optional(odm.Integer(), description="The size (in bytes) of the analyzed file pertinent to the result.")
    drop_file = odm.Boolean(default=False, description="A flag indicating whether the file should be excluded from subsequent analysis stages.", ai=False)
    from_archive = odm.Boolean(index=False, default=False, description="Indicates whether the result was retrieved from an archive rather than produced from a recent analysis.", ai=False)

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
