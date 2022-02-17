from assemblyline import odm


class Sandbox(odm.Model):
    # Perceived capabilities that the file may have
    capabilities = odm.Optional(odm.List(odm.Text()))
