from assemblyline.common import forge

from assemblyline import odm
from assemblyline.odm.models.heuristic import CATEGORIES
from assemblyline.odm.models.tagging import Tagging

BODY_TYPES = {"TEXT", "MEMORY_DUMP", "GRAPH_DATA", "URL", "JSON"}
constants = forge.get_constants()


@odm.model(index=True, store=False)
class Heuristic(odm.Model):
    heur_id = odm.Keyword(copyto="__text__")                                 # Triggered heuristic
    category = odm.Optional(odm.Enum(values=CATEGORIES, copyto="__text__"))  # Heuristic's category
    score = odm.Integer()                                                    # Heuristic's score


@odm.model(index=True, store=False)
class Section(odm.Model):
    body = odm.Optional(odm.Text(copyto="__text__"))        # Text body of the result section
    classification = odm.Classification()                   # Classification of the section
    body_format = odm.Enum(values=BODY_TYPES, index=False)  # Type of body in this section
    depth = odm.Integer(index=False)                        # Depth of the section
    heuristic = odm.Optional(odm.Compound(Heuristic))       # Heuristic used to score result section
    tags = odm.Compound(Tagging, default={})                # List of tags associated to this section
    title_text = odm.Text(copyto="__text__")                # Title of the section


@odm.model(index=True, store=True)
class ResultBody(odm.Model):
    score = odm.Integer(default=0)                          # Aggregate of the score for all heuristics
    sections = odm.List(odm.Compound(Section), default=[])  # List of sections


@odm.model(index=False, store=False)
class Milestone(odm.Model):
    service_started = odm.Date(default="NOW")    # Date the service started scanning
    service_completed = odm.Date(default="NOW")  # Date the service finished scanning


@odm.model(index=True, store=False)
class File(odm.Model):
    name = odm.Keyword(copyto="__text__")      # Name of the file
    sha256 = odm.Keyword(copyto="__text__")    # SHA256 hash of the file
    description = odm.Text(copyto="__text__")  # Description of the file
    classification = odm.Classification()      # Classification of the file


@odm.model(index=True, store=True)
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone, default={})                          # Milestone block
    service_version = odm.Keyword(store=False)                                # Version of the service that ran on the file
    service_name = odm.Keyword(copyto="__text__")                             # Name of the service that scan the file
    service_tool_version = odm.Optional(odm.Keyword(copyto="__text__"))       # Tool version of the service
    supplementary = odm.List(odm.Compound(File), default=[])                  # List of supplementary files
    extracted = odm.List(odm.Compound(File), default=[])                      # List of extracted files
    service_context = odm.Optional(odm.Keyword(index=False, store=False))     # Context about the service that was running
    service_debug_info = odm.Optional(odm.Keyword(index=False, store=False))  # Debug information where the service was processed


@odm.model(index=True, store=True)
class Result(odm.Model):
    classification = odm.Classification()                      # Aggregate classification for the result
    created = odm.Date(default="NOW")                          # Date at which the result object got created
    expiry_ts = odm.Date(store=False)                          # Expiry time stamp
    response: ResponseBody = odm.Compound(ResponseBody)        # The body of the response from the service
    result: ResultBody = odm.Compound(ResultBody, default={})  # The result body
    sha256 = odm.Keyword(store=False)                          # SHA256 of the file the result object relates to
    drop_file = odm.Boolean(default=False)                     # After this service is done, further stages don't need to run

    def build_key(self, conf_key=None):
        return self.help_build_key(
            self.sha256,
            self.response.service_name,
            self.response.service_version,
            conf_key
        )

    @staticmethod
    def help_build_key(sha256, service_name, service_version, conf_key=None):
        key_list = [
            sha256,
            service_name.replace('.', '_'),
            f"v{service_version.replace('.', '_')}"
        ]

        if conf_key:
            key_list.append('c' + conf_key.replace('.', '_'))
        else:
            key_list.append("c0")

        return '.'.join(key_list)

    def is_empty(self):
        if len(self.response.extracted) == 0 and \
                len(self.response.supplementary) == 0 and \
                len(self.result.sections) == 0 and \
                self.result.score == 0:
            return True
        return False
