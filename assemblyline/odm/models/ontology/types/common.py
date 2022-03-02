from assemblyline import odm

# Complex Types


class FileInfo(odm.Model):
    md5 = odm.MD5()
    sha1 = odm.SHA1()
    sha256 = odm.SHA256()
    type = odm.Keyword()
    size = odm.Integer()
