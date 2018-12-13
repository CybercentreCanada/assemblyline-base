from assemblyline import odm

BODY_TYPES = {"TEXT", "MEMORY_DUMP", "GRAPH_DATA", "URL", "JSON"}
TAG_USAGE = {"CORRELATION", "IDENTIFICATION", "INFO", "IGNORE"}


@odm.model(index=True, store=True)
class Section(odm.Model):
    section_id = odm.Integer()                 # ID of the section to generate the tree
    body = odm.Text()                          # Text body of the result section
    classification = odm.Classification()      # Classification of the section
    links = odm.List(odm.Keyword())            # List of links TODO: are we using this? Remove ?
    truncated = odm.Boolean()                  # is the result section truncated of not
    finalized = odm.Boolean()                  # is the result section finalized or not
    title_text = odm.Text()                    # Title of the section
    depth = odm.Integer()                      # Depth of the section
    parent_section_id = odm.Integer()          # ID of the parent section
    score = odm.Integer()                      # Score of the section
    body_format = odm.Enum(values=BODY_TYPES)  # Type of body in this section


@odm.model(index=True, store=True)
class Tag(odm.Model):
    weight = odm.Integer()                 # weight score of the tag TODO: remove?
    classification = odm.Classification()  # Classification of the tag
    value = odm.Keyword()                  # Value of the tag
    context = odm.Keyword()                # Context of the tag
    usage = odm.Enum(values=TAG_USAGE)     # Usage of the tag TODO: remove?
    type = odm.Keyword()                   # Type of tag TODO: Enum?


@odm.model(index=True, store=True)
class ResultBody(odm.Model):
    tag_score = odm.Integer()                   # Aggregate score of all tags TODO: remove?
    context = odm. Keyword()                    # Context for the tags?? TODO: Remove?
    classification = odm.Classification()       # Classification of the result body? TODO: redundant?
    truncated = odm.Boolean()                   # is the result body truncated or not
    tags = odm.List(odm.Compound(Tag))          # List of tag objects
    score = odm.Integer()                       # Aggregate of the score for all sections
    default_usage = odm.Keyword()               # No clue what that is used for TODO: Remove?
    sections = odm.List(odm.Compound(Section))  # List of sections


@odm.model(index=True, store=True)
class Milestone(odm.Model):
    service_started = odm.Date()    # Date the service started scanning
    service_completed = odm.Date()  # Date the service finished scanning


@odm.model(index=True, store=True)
class File(odm.Model):
    name = odm.Keyword()                   # Name of the file
    sha256 = odm.Keyword()                 # SHA256 hash of the file
    description = odm.Text()               # Description of the file
    classification = odm.Classification()  # Classification of the file


@odm.model(index=True, store=True)
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone)          # Milestone block
    service_version = odm.Keyword()               # Version of the service that ran on the file
    service_name = odm.Keyword()                  # Name of the service that scan the file
    supplementary = odm.List(odm.Compound(File))  # List of supplementary files
    extracted = odm.List(odm.Compound(File))      # List of extracted files
    service_context = odm.Keyword()               # Context about the service that was running
    service_debug_info = odm.Keyword()            # Debug information about where the service was processed


@odm.model(index=True, store=True)
class Result(odm.Model):
    classification = odm.Classification()  # Aggregate classification for the result
    created = odm.Date()                   # Date at which the result objec got created
    expiry_ts = odm.Date()                 # Expiry time stamp
    response = odm.Compound(ResponseBody)  # The body of the response from the service
    result = odm.Compound(ResultBody)      # The result body
    sha256 = odm.Keyword()                 # SHA256 of the file the result object relates to

    @staticmethod
    def build_key(service_name, version, conf_key, file_hash):
        key_list = [file_hash, service_name.replace('.', '_')]
        if version:
            key_list.append('v' + version.replace('.', '_'))
        if conf_key:
            key_list.append('c' + conf_key.replace('.', '_'))
        key = '.'.join(key_list)
        return key
