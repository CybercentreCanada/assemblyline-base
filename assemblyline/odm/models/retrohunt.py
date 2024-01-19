from assemblyline import odm


INDEX_CATAGORIES = [
    'hot',
    'archive',
    'hot_and_archive',
]


@odm.model(index=True, store=True, description="A search run on stored files.")
class Retrohunt(odm.Model):
    # Metadata
    indices = odm.Enum(INDEX_CATAGORIES, default='hot_and_archive',
                       description="Defines the indices used for this retrohunt job")
    classification = odm.Classification(description="Classification for the retrohunt job")
    search_classification = odm.ClassificationString(description="Maximum classification of results in the search")
    creator = odm.keyword(copyto="__text__", description="User who created this retrohunt job")
    description = odm.Text(copyto="__text__", description="Human readable description of this retrohunt job")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp of this retrohunt job")

    start_group = odm.integer(description="Earliest expiry group this search will include")
    end_group = odm.integer(description="Latest expiry group this search will include")
    
    created_time = odm.date(description="Start time for the search.")
    started_time = odm.date(description="Start time for the search.")
    completed_time = odm.Optional(odm.Date(store=False), description="Time that the search ended")
    
    # Search data
    code = odm.keyword(description="Unique code identifying this retrohunt job")
    raw_query = odm.keyword(store=False, description="Text of filter query derived from yara signature")
    yara_signature = odm.keyword(copyto="__text__", store=False, description="Text of original yara signature run")

    # Completion data
    errors = odm.sequence(odm.keyword(store=False), store=False,
                          description="List of error messages that occured during the search")
    warnings = odm.sequence(odm.keyword(store=False), store=False,
                            description="List of warning messages that occured during the search")
    finished = odm.boolean(default=False, description="Boolean that indicates if this retrohunt job is finished")
    truncated = odm.boolean(default=False, description="Indicates if the list of hits been truncated at some limit")


@odm.model(index=True, store=True, description="A hit encountered during a retrohunt search.")
class RetrohuntHit(odm.Model):
    classification = odm.Classification(description="Classification string for the retrohunt job and results list")
    sha256 = odm.SHA256()
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry for this entry.")
    search = odm.keyword()
