from assemblyline import odm
from .service import EnvironmentVariable


@odm.model(index=False, store=False)
class DockerConfigDelta(odm.Model):
    image = odm.Optional(odm.Keyword())                    # Complete name of the Docker image with tag
    command = odm.Optional(odm.Keyword())
    environment = odm.List(odm.Compound(EnvironmentVariable), default=[])
    dependencies = odm.Optional(odm.List(odm.Keyword()))   # List of other required Docker container(s)
    network = odm.Optional(odm.List(odm.Keyword()))        # Network access rules


@odm.model(index=False, store=False)
class SubmissionParamsDelta(odm.Model):
    default = odm.Optional(odm.Any())
    name = odm.Optional(odm.Keyword())
    type = odm.Optional(odm.Enum(values=['str', 'int', 'list', 'bool']))
    value = odm.Optional(odm.Any())


@odm.model(index=False, store=False)
class ServiceDelta(odm.Model):
    accepts = odm.Optional(odm.Keyword(), index=True, store=False)
    rejects = odm.Optional(odm.Keyword(), index=True, store=False)

    category = odm.Optional(odm.Keyword(), index=True, store=False, copyto="__text__")
    config = odm.Optional(odm.Mapping(odm.Any()))
    cpu_cores = odm.Optional(odm.Float())
    description = odm.Optional(odm.Text(), index=True, store=False, copyto="__text__")
    enabled = odm.Optional(odm.Boolean(), index=True, store=False)
    install_by_default = odm.Optional(odm.Boolean())
    is_external = odm.Optional(odm.Boolean())
    licence_count = odm.Optional(odm.Integer())

    name = odm.Optional(odm.Keyword(), index=True, store=False, copyto="__text__")
    version = odm.Keyword(index=True, store=True)

    ram_mb = odm.Optional(odm.Integer())

    disable_cache = odm.Optional(odm.Boolean())

    stage = odm.Optional(odm.Keyword(), index=True, store=False, copyto="__text__")
    submission_params = odm.Optional(odm.List(odm.Compound(SubmissionParamsDelta)))
    supported_platforms = odm.Optional(odm.List(odm.Enum(values=["windows", "linux"])))
    timeout = odm.Optional(odm.Integer())

    docker_config: DockerConfigDelta = odm.Optional(odm.Compound(DockerConfigDelta))
