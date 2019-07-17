from assemblyline import odm


ALLOWED_VERDICTS = ["malicious", "highly suspicious", "suspicious", "no threat detected", "safe"]
ALLOWED_COLLECTION = ['submission', 'result']

@odm.model(index=True, store=True)
class Verdict(odm.Model):
    collection = odm.Enum(values=ALLOWED_COLLECTION)  # Collection targeted by the verdict
    collection_id = odm.Keyword()                     # Document in the collection targeted by the verdict
    date = odm.Date()                                 # Date the verdict occurred
    user = odm.Keyword()                              # User who made the verdict
    verdict = odm.Enum(values=ALLOWED_VERDICTS)       # Verdict that the document should have been