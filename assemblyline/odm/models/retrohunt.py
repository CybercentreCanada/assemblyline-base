from assemblyline import odm


@odm.model(index=True, store=True, description="A search run on stored files.")
class Retrohunt(odm.Model):
    # Metadata
    creator = odm.keyword()
    tags = odm.mapping(odm.sequence(odm.keyword()))
    description = odm.Text()
    created = odm.date(default='NOW', description="Start time for the search.")
    classification = odm.Classification(description="Classification of the search")
    # expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")

    # Search data
    yara_signature = odm.keyword()
    raw_query = odm.keyword()
    code = odm.keyword()

    # Completion data
    # finished = odm.boolean(default=False)
    # truncated = odm.boolean(default=False)
    # hits = odm.sequence(odm.keyword())
    # error = odm.sequence(odm.keyword())