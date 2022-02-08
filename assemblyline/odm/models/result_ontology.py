from assemblyline import odm
from assemblyline.common import forge

Classification = forge.get_classification()

# Complex Types
class FileInfo(odm.Model):
    md5 = odm.MD5()
    sha1 = odm.SHA1()
    sha256 = odm.SHA256()
    type = odm.Keyword()
    size = odm.Integer()

# Category Bases
@odm.model(index=False, store=False)
class Antivirus(odm.Model):
    class Detection(odm.Model):
        class Engine(odm.Model):
            definition =odm.Optional(odm.Text())
            name = odm.Keyword()
            version = odm.Optional(odm.Keyword())

        category = odm.Optional(odm.Keyword())
        engine = odm.Compound(Engine)
        verdict = odm.Keyword()

    detections = odm.List(odm.Compound(Detection))

    #VirusTotal-specific
    capabilities = odm.Optional(odm.List(odm.Text()))

# Result Base
@odm.model(index=False, store=False)
class ResultOntology(odm.Model):
    class ServiceInfo(odm.Model):
        name = odm.Keyword()
        version = odm.Keyword()
        tool_version = odm.Optional(odm.Keyword())
        date = odm.Date()
        classification = odm.Keyword(default=Classification.UNRESTRICTED)

    service_info = odm.Compound(ServiceInfo)
    file_info = odm.Compound(FileInfo)
    antivirus = odm.Optional(odm.Compound(Antivirus))
