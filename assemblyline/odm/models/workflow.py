from assemblyline import odm

PRIORITIES = {"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
STATUSES = {"", "MALICIOUS", "NON-MALICIOUS", "ASSESS"}


@odm.model(index=True, store=True)
class Workflow(odm.Model):
    classification = odm.Classification(copyto="__text__")  # Classification of the workflow
    creation_date = odm.Date()                              # Creation date of the workflow
    creator = odm.Keyword()                                 # UID of the creator
    edited_by = odm.Keyword()                               # UID of the last edit user
    hit_count = odm.Integer()                               # Number of time workflow hit
    label = odm.List(odm.Keyword(), copyto="__text__")      # Labels applied by the workflow
    last_edit = odm.Date()                                  # Last edit date
    last_seen = odm.Date()                                  # Last hit date
    name = odm.Keyword(copyto="__text__")                   # Name of the workflow
    priority = odm.Enum(values=PRIORITIES, default="")      # Priority applied by the workflow
    query = odm.Keyword()                                   # Query that the workflow runs
    status = odm.Enum(values=STATUSES, default="")          # Status applied by the workflow
    workflow_id = odm.Keyword()                             # ID of the workflow
