from assemblyline import odm


@odm.model(index=True, store=True)
class Seen(odm.Model):    # Seen block
    count = odm.Integer()  # Number of time we've seen this file
    first = odm.Date()     # Date of the first time we've seen the file
    last = odm.Date()      # Date of the last time we've seen the file


@odm.model(index=True, store=True)
class File(odm.Model):
    ascii = odm.Keyword()                  # Dotted ascii representation of the first 64 bytes of the file
    classification = odm.Classification()  # Classification of the file
    entropy = odm.Float()                  # Entropy of the file
    hex = odm.Keyword()                    # Hex dump of the first 64 bytes of the file
    md5 = odm.Keyword()                    # MD5 of the top level file
    magic = odm.Keyword()                  # Output from libmagic related to that file
    mime = odm.Keyword()                   # Mime type of the file as identified by libmagic
    name = odm.Keyword()                   # Name of the file
    seen = odm.Compound(Seen)              # Attributes about when the file was seen
    sha1 = odm.Keyword()                   # SHA1 hash of the file
    sha256 = odm.Keyword()                 # SHA256 hash of the file
    size = odm.Integer()                   # Size of the file
    ssdeep = odm.Keyword()                 # SSDEEP hash of the file
    type = odm.Keyword()                   # Type of file as identified by Assemblyline
