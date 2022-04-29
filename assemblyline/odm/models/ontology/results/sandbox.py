from assemblyline import odm


@odm.model(description="Sandbox Ontology Model")
class Sandbox(odm.Model):
    @odm.model(description="The metadata of the analysis, per analysis")
    class AnalysisMetadata(odm.Model):
        @odm.model(description="The metadata regarding the machine where the analysis took place")
        class MachineMetadata(odm.Model):
            ip = odm.Optional(odm.IP(), description="The IP of the machine used for analysis")
            hypervisor = odm.Optional(odm.Keyword(), description="The hypervisor of the machine used for analysis")
            hostname = odm.Optional(odm.Keyword(), description="The name of the machine used for analysis")
            platform = odm.Optional(odm.Platform(), description="The platform of the machine used for analysis")
            version = odm.Optional(odm.Keyword(),
                                   description="The version of the operating system of the machine used for analysis")
            architecture = odm.Optional(odm.Processor(),
                                        description="The architecture of the machine used for analysis")

        task_id = odm.Optional(odm.Keyword(), description="The ID used for identifying the analysis task")
        start_time = odm.Date(description="The start time of the analysis")
        end_time = odm.Date(description="The end time of the analysis")
        routing = odm.Optional(odm.Keyword(),
                               description="The routing used in the sandbox setup (Spoofed, Internet, Tor, VPN)")
        machine_metadata = odm.Optional(odm.Compound(MachineMetadata), description="The metadata of the analysis")

    oid = odm.UUID(description="Unique identifier of ontology")
    oid_parent = odm.Optional(odm.UUID(), description="Parent of this ontology")
    oid_children = odm.Optional(odm.List(odm.UUID()), description="Children of this ontology")
    oid_children = odm.Optional(odm.List(odm.UUID()), description="Children of this ontology")
    analysis_metadata = odm.Compound(AnalysisMetadata, description="Metadata for the analysis")
    sandbox_name = odm.Keyword(description="The name of the sandbox")
    sandbox_version = odm.Optional(odm.Keyword(), description="The version of the sandbox")
