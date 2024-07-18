from assemblyline import odm
from assemblyline.odm.models.ontology.filetypes import PE


@odm.model(description="File Characteristics")
class File(odm.Model):
    # Common information
    md5 = odm.MD5(description="MD5 of file")
    sha1 = odm.SHA1(description="SHA1 of file")
    sha256 = odm.SHA256(description="SHA256 of file")
    type = odm.Optional(odm.Keyword(description="Type of file as identified by Assemblyline"))
    size = odm.Integer(description="Size of the file in bytes")
    names = odm.Optional(odm.List(odm.Text()), description="Known filenames associated to file")
    parent = odm.Optional(odm.SHA256(), description="Absolute parent of file relative to submission")

    # Specialized information (List from Tagging.File)
    # apk = odm.Optional(odm.Compound(APK), description="APK File Properties")
    # jar = odm.Optional(odm.Compound(JAR), description="JAR File Properties")
    # img = odm.Optional(odm.Compound(IMG), description="Image File Properties")
    # ole = odm.Optional(odm.Compound(OLE), description="OLE File Properties")
    pe = odm.Optional(odm.Compound(PE), description="Properties related to PE")
    # pdf = odm.Optional(odm.Compound(PDF), description="PDF File Properties")
    # plist = odm.Optional(odm.Compound(PList), description="PList File Properties")
    # powershell = odm.Optional(odm.Compound(PowerShell), description="PowerShell File Properties")
    # shortcut = odm.Optional(odm.Compound(Shortcut), description="Shortcut File Properties")
    # swf = odm.Optional(odm.Compound(SWF), description="SWF File Properties")
