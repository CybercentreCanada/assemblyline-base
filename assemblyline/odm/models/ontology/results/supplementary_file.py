from assemblyline import odm


@odm.model(index=False, store=False, description="Logs related to the analysis")
class SupplementaryFile(odm.Model):
    encoding = odm.Enum(values=['raw', 'base64'], description="Encoding of the file appended")
    source = odm.Keyword(description="Where did the file originate from?")
    filename = odm.Text(description="The name of the file")
    content = odm.Text(description="The content of the file")
