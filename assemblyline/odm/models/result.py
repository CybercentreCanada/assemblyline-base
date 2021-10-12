from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.caching import generate_conf_key
from assemblyline.odm.models.tagging import Tagging


BODY_FORMAT = {"TEXT", "MEMORY_DUMP", "GRAPH_DATA", "URL", "JSON", "KEY_VALUE", "PROCESS_TREE", "TABLE", "IMAGE"}
constants = forge.get_constants()


@odm.model(index=True, store=False)
class Attack(odm.Model):
    attack_id = odm.Keyword(copyto="__text__")  # Attack matrix ID
    pattern = odm.Keyword(copyto="__text__")                        # Attack matrix Pattern Name
    categories = odm.List(odm.Keyword())                            # Attack matrix Categories


@odm.model(index=True, store=False)
class Signature(odm.Model):
    name = odm.Keyword(copyto="__text__")   # Name of the signature that triggered the heuristic
    frequency = odm.Integer(default=1)      # Number of times this signature triggered the heuristic
    safe = odm.Boolean(default=False)       # Is the signature safelisted or not


@odm.model(index=True, store=False)
class Heuristic(odm.Model):
    heur_id = odm.Keyword(copyto="__text__")                    # ID of th heuristic triggered
    name = odm.Keyword(copyto="__text__")                       # Name of the heuristic
    attack = odm.List(odm.Compound(Attack), default=[])         # List of Att&ck IDs related to this heuristic
    signature = odm.List(odm.Compound(Signature), default=[])   # List of signatures that triggered the heuristic
    score = odm.Integer()                                       # Computed Heuristic's score


@odm.model(index=True, store=False)
class Section(odm.Model):
    auto_collapse = odm.Boolean(default=False)                          # Should the section be collapsed when displayed
    body = odm.Optional(odm.Text(copyto="__text__"))                    # Text body of the result section
    classification = odm.Classification()                               # Classification of the section
    body_format = odm.Enum(values=BODY_FORMAT, index=False)             # Type of body in this section
    depth = odm.Integer(index=False)                                    # Depth of the section
    heuristic = odm.Optional(odm.Compound(Heuristic))                   # Heuristic used to score result section
    tags = odm.Compound(Tagging, default={})                            # List of tags associated to this section
    safelisted_tags = odm.FlattenedListObject(store=False, default={})  # List of safelisted tags
    title_text = odm.Text(copyto="__text__")                            # Title of the section


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
    name = odm.Keyword(copyto="__text__")           # Name of the file
    sha256 = odm.SHA256(copyto="__text__")          # SHA256 hash of the file
    description = odm.Text(copyto="__text__")       # Description of the file
    classification = odm.Classification()           # Classification of the file
    is_section_image = odm.Boolean(defautl=False)   # Is this an image used in an Image Result Section


@odm.model(index=True, store=True)
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone, default={})                          # Milestone block
    service_version = odm.Keyword(store=False)                                # Version of the service
    service_name = odm.Keyword(copyto="__text__")                             # Name of the service that scan the file
    service_tool_version = odm.Optional(odm.Keyword(copyto="__text__"))       # Tool version of the service
    supplementary = odm.List(odm.Compound(File), default=[])                  # List of supplementary files
    extracted = odm.List(odm.Compound(File), default=[])                      # List of extracted files
    service_context = odm.Optional(odm.Keyword(index=False, store=False))     # Context about the service
    service_debug_info = odm.Optional(odm.Keyword(index=False, store=False))  # Debug info about the service


@odm.model(index=True, store=True)
class Result(odm.Model):
    archive_ts = odm.Date(store=False)                         # Archiving timestamp
    classification = odm.Classification()                      # Aggregate classification for the result
    created = odm.Date(default="NOW")                          # Date at which the result object got created
    expiry_ts = odm.Optional(odm.Date(store=False))            # Expiry time stamp
    response: ResponseBody = odm.Compound(ResponseBody)        # The body of the response from the service
    result: ResultBody = odm.Compound(ResultBody, default={})  # The result body
    sha256 = odm.SHA256(store=False)                           # SHA256 of the file the result object relates to
    drop_file = odm.Boolean(default=False)                     # Do not pass to other stages after this run

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

    def is_empty(self):
        if len(self.response.extracted) == 0 and \
                len(self.response.supplementary) == 0 and \
                len(self.result.sections) == 0 and \
                self.result.score == 0:
            return True
        return False
