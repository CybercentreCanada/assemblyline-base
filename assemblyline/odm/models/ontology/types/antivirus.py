from assemblyline import odm


@odm.model(description="Antivirus Ontology Model")
class Antivirus(odm.Model):
    @odm.model(description="Antivirus Detection Model")
    class Detection(odm.Model):
        @odm.model(description="Antivirus Engine Model")
        class Engine(odm.Model):
            definition_version = odm.Optional(odm.Keyword(), description="Version of definition set")
            name = odm.Keyword(description="Name of antivirus engine")
            version = odm.Optional(odm.Keyword(), description="Version of antivirus engine")

        # What category does the verdict fall under?
        category = odm.Optional(odm.Enum(['type-unsupported',
                                          'undetected',
                                          'failure',
                                          'suspicious',
                                          'malicious']),
                                description="What category does the verdict fall under?<br><ul>"
                                "<li>`type-unsupported`: File sent to antivirus is unsupported</li>"
                                "<li>`undetected`: File not detected by antivirus</li>"
                                "<li>`failure`: Antivirus failed during detection</li>"
                                "<li>`suspicious`: Antivirus deems suspicious</li>"
                                "<li>`malicious`: Antivirus deems malicious</li></ul>")
        engine = odm.Compound(Engine, description="Antivirus engine information")
        virus_name = odm.Optional(odm.Keyword(), description="The name of the virus")

    odm_version = odm.Text(default="1.0", description="Version of antivirus ontological result")
    detections = odm.List(odm.Compound(Detection), description="List of antivirus detections")
