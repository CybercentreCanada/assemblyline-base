from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


PRIORITIES = {None, "LOW", "MEDIUM", "HIGH", "CRITICAL"}
STATUSES = {None, "MALICIOUS", "NON-MALICIOUS", "ASSESS", "TRIAGE"}


@odm.model(index=True, store=True)
class Workflow(odm.Model):
    classification = odm.Classification(
        copyto="__text__",
        default=Classification.UNRESTRICTED)                                     #  Classification of the workflow
    creation_date = odm.Date(default="NOW")                                      # Creation date of the workflow
    creator = odm.Keyword()                                                      # UID of the creator
    edited_by = odm.Keyword()                                                    # UID of the last edit user
    hit_count = odm.Integer(default=0)                                           # Number of time workflow hit
    labels = odm.List(odm.Keyword(), copyto="__text__", default=[])              # Labels applied by the workflow
    last_edit = odm.Date(default="NOW")                                          # Last edit date
    last_seen = odm.Date(default_set=True)                                       # Last hit date
    name = odm.Keyword(copyto="__text__")                                        # Name of the workflow
    priority = odm.Enum(copyto="__text__", values=PRIORITIES, default_set=True)  # Priority applied by the workflow
    query = odm.Keyword()                                                        # Query that the workflow runs
    status = odm.Enum(copyto="__text__", values=STATUSES, default_set=True)      # Status applied by the workflow
    workflow_id = odm.UUID(default_set=True)                                     # ID of the workflow
