from assemblyline import odm


class Antivirus(odm.Model):
    class Detection(odm.Model):
        class Engine(odm.Model):
            definition_version = odm.Optional(odm.Keyword())                    # Version of definition set
            name = odm.Keyword()                                                # Name of AV engine
            version = odm.Optional(odm.Keyword())                               # Version of AV engine

        # What category does the verdict fall under?
        category = odm.Optional(odm.Enum(['type-unsupported',                   # File sent to AV is unsupported
                                          'undetected',                         # File not detected by AV
                                          'failure',                            # AV failed during detection
                                          'harmless',                           # AV deems harmless
                                          'suspicious',                         # AV deems suspicious
                                          'malicious']))                        # AV deems malicious
        engine = odm.Compound(Engine)
        virus_name = odm.Optional(odm.Keyword())                                # The name of the virus

    odm_version = odm.Text(default="1.0")                                       # Version of AV ontological result
    detections = odm.List(odm.Compound(Detection))                              # List of AV detections
