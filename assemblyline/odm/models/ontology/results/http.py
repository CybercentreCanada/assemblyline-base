from assemblyline import odm
from assemblyline.odm.models.ontology.file import File


@odm.model(index=False, store=False, description="")
class HTTPRedirect(odm.Model):
    from_url = odm.Keyword(description="")
    to_url = odm.Keyword(description="")


@odm.model(index=False, store=False, description="HTTP Task")
class HTTP(odm.Model):
    response_code = odm.Integer(description="The status code of the main page")
    redirection_url = odm.Optional(odm.Keyword(), description="The final page of the requested url")
    redirects = odm.Optional(odm.List(odm.Compound(HTTPRedirect)), description="List of Redirects")
    favicon = odm.Optional(odm.Compound(File), description="The file information of the main favicon")
    title = odm.Optional(odm.Keyword(), description="The title of the main page after any redirection")
