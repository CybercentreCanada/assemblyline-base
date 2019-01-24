from assemblyline import odm

BODY_TYPES = {"TEXT", "MEMORY_DUMP", "GRAPH_DATA", "URL", "JSON"}


@odm.model(index=True, store=False)
class Section(odm.Model):
    section_id = odm.Integer(index=False)                   # ID of the section to generate the tree
    body = odm.Text(copyto="__text__")                      # Text body of the result section
    classification = odm.Classification()                   # Classification of the section
    truncated = odm.Boolean(index=False)                    # is the result section truncated of not
    finalized = odm.Boolean(index=False)                    # is the result section finalized or not
    title_text = odm.Text(copyto="__text__")                # Title of the section
    depth = odm.Integer(index=False)                        # Depth of the section
    parent_section_id = odm.Integer(index=False)            # ID of the parent section
    score = odm.Integer(index=False)                        # Score of the section
    body_format = odm.Enum(values=BODY_TYPES, index=False)  # Type of body in this section


@odm.model(index=True, store=False)
class Tag(odm.Model):
    classification = odm.Classification()   # Classification of the tag
    value = odm.Keyword(copyto="__text__")  # Value of the tag
    context = odm.Keyword()                 # Context of the tag
    type = odm.Keyword()                    # Type of tag TODO: Enum?


@odm.model(index=True, store=True)
class ResultBody(odm.Model):
    truncated = odm.Boolean(index=False, store=False)  # is the result body truncated or not
    tags = odm.List(odm.Compound(Tag))                 # List of tag objects
    score = odm.Integer()                              # Aggregate of the score for all sections
    sections = odm.List(odm.Compound(Section))         # List of sections


@odm.model(index=False, store=False)
class Milestone(odm.Model):
    service_started = odm.Date()    # Date the service started scanning
    service_completed = odm.Date()  # Date the service finished scanning


@odm.model(index=True, store=False)
class File(odm.Model):
    name = odm.Keyword(copyto="__text__")      # Name of the file
    sha256 = odm.Keyword(copyto="__text__")    # SHA256 hash of the file
    description = odm.Text(copyto="__text__")  # Description of the file
    classification = odm.Classification()      # Classification of the file


@odm.model(index=True, store=True)
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone)                        # Milestone block
    service_version = odm.Keyword(store=False)                  # Version of the service that ran on the file
    service_name = odm.Keyword(copyto="__text__")               # Name of the service that scan the file
    supplementary = odm.List(odm.Compound(File))                # List of supplementary files
    extracted = odm.List(odm.Compound(File))                    # List of extracted files
    service_context = odm.Keyword(index=False, store=False)     # Context about the service that was running
    service_debug_info = odm.Keyword(index=False, store=False)  # Debug information where the service was processed


@odm.model(index=True, store=True)
class Result(odm.Model):
    classification = odm.Classification()   # Aggregate classification for the result
    created = odm.Date(default="NOW")       # Date at which the result object got created
    expiry_ts = odm.Date(store=False)       # Expiry time stamp
    oversized = odm.Boolean(default=False)  # Is an oversized record
    response = odm.Compound(ResponseBody)   # The body of the response from the service
    result = odm.Compound(ResultBody)       # The result body
    sha256 = odm.Keyword(store=False)       # SHA256 of the file the result object relates to

    def build_key(self, conf_key=None):
        key_list = [
            self.sha256,
            self.response.service_name.replace('.', '_'),
            f"v{self.response.service_version.replace('.', '_')}"
        ]

        if conf_key:
            key_list.append('c' + conf_key.replace('.', '_'))
        else:
            key_list.append("c0")

        return '.'.join(key_list)
