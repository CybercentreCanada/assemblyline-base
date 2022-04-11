from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


PRIORITIES = {None, "LOW", "MEDIUM", "HIGH", "CRITICAL"}
STATUSES = {None, "MALICIOUS", "NON-MALICIOUS", "ASSESS", "TRIAGE"}


@odm.model(index=True, store=True, description="Model of Workflow")
class Workflow(odm.Model):
    classification = odm.Classification(copyto="__text__", default=Classification.UNRESTRICTED,
                                        description="Classification of the workflow")
    creation_date = odm.Date(default="NOW", description="Creation date of the workflow")
    creator = odm.Keyword(description="UID of the creator of the workflow")
    edited_by = odm.Keyword(description="UID of the last user to edit the workflow")
    hit_count = odm.Integer(default=0, description="Number of times there was a workflow hit")
    labels = odm.List(odm.Keyword(), copyto="__text__", default=[], description="Labels applied by the workflow")
    last_edit = odm.Date(default="NOW", description="Date of last edit on workflow")
    last_seen = odm.Optional(odm.Date(), description="Date of last hit on workflow")
    name = odm.Keyword(copyto="__text__", description="Name of the workflow")
    priority = odm.Optional(odm.Enum(copyto="__text__", values=PRIORITIES),
                            description="Priority applied by the workflow")
    query = odm.Keyword(description="Query that the workflow runs")
    status = odm.Optional(odm.Enum(copyto="__text__", values=STATUSES), description="Status applied by the workflow")
    workflow_id = odm.Optional(odm.UUID(), description="ID of the workflow")
