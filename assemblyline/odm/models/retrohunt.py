from assemblyline import odm


@odm.model(index=True, store=True, description="A search run on stored files.")
class Retrohunt(odm.Model):
    # Metadata
    archive_only = odm.boolean(default=False, description="Defines the indices used for this retrohunt job")
    classification = odm.Classification(description="Classification string for the retrohunt job and results list")
    created = odm.date(default='NOW', description="Start time for the search.")
    creator = odm.keyword(copyto="__text__", description="User who created this retrohunt job")
    description = odm.Text(copyto="__text__", description="Human readable description of this retrohunt job")
    tags = odm.mapping(odm.sequence(odm.keyword(copyto="__text__")), description="Tags describing this retrohunt job")
    # expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")

    # Search data
    code = odm.keyword(description="Unique code identifying this retrohunt job")
    raw_query = odm.keyword(description="Text of filter query derived from yara signature")
    yara_signature = odm.keyword(copyto="__text__", description="Text of original yara signature run")

    # Completion data
    errors = odm.sequence(odm.keyword(), description="List of error messages that occured during the search")
    finished = odm.boolean(default=False, description="Boolean that indicates if this retrohunt job is finished")
    hits = odm.sequence(odm.keyword(store=False), store=False,
                        description="List of sha256 of the files that were hit during the search")
    percentage = odm.Optional(odm.integer(), description="Percentage of completion the phase is at")
    phase = odm.Optional(odm.Enum(['filtering', 'yara', 'finished'], description="Phase the job is at"))
    progress = odm.Optional(odm.sequence(odm.integer()), description="Progress values when the job is running")
    total_errors = odm.Optional(odm.integer(), description="Total number of errors encountered during the job")
    total_hits = odm.Optional(odm.integer(), description="Total number of hits when the job first ran")
    truncated = odm.boolean(default=False, description="Indicates if the list of hits been truncated at some limit")
