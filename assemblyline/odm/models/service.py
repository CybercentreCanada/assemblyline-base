from typing import List, Optional as Opt

from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.constants import DEFAULT_SERVICE_ACCEPTS, DEFAULT_SERVICE_REJECTS

Classification = forge.get_classification()


@odm.model(index=False, store=False)
class EnvironmentVariable(odm.Model):
    name = odm.Keyword()
    value = odm.Keyword()


@odm.model(index=False, store=False)
class DockerConfig(odm.Model):
    allow_internet_access: bool = odm.Boolean(default=False)
    command: Opt[List[str]] = odm.Optional(odm.List(odm.Keyword()))
    cpu_cores: float = odm.Float(default=1.0)
    environment: List[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[])
    image: str = odm.Keyword()                                 # Complete name of the Docker image with tag
    ram_mb: int = odm.Integer(default=1024)


@odm.model(index=False, store=False)
class UpdateSource(odm.Model):
    name = odm.Keyword()
    password = odm.Optional(odm.Keyword())
    pattern = odm.Optional(odm.Keyword())
    private_key = odm.Optional(odm.Keyword())
    uri = odm.Keyword()
    username = odm.Optional(odm.Keyword())
    headers = odm.List(odm.Compound(EnvironmentVariable), default=[])


@odm.model(index=False, store=False)
class UpdateConfig(odm.Model):
    # build_options = odm.Optional(odm.Compound(DockerfileConfig))  # If we are going to build a container, how?
    generates_signatures = odm.Boolean(index=True, default=False)
    method = odm.Enum(values=['run', 'build'])                    # Are we going to run or build a container?
    run_options = odm.Optional(odm.Compound(DockerConfig))        # If we are going to run a container, which one?
    sources = odm.List(odm.Compound(UpdateSource), default=[])    # Generic external resources we need
    update_interval_seconds = odm.Integer()                       # Update check interval in seconds


@odm.model(index=False, store=False)
class SubmissionParams(odm.Model):
    default = odm.Any()
    name = odm.Keyword()
    type = odm.Enum(values=['str', 'int', 'list', 'bool'])
    value = odm.Any()


@odm.model(index=True, store=False)
class Service(odm.Model):
    # Regexes applied to assemblyline style file type string
    accepts = odm.Keyword(store=True, default=DEFAULT_SERVICE_ACCEPTS)
    rejects = odm.Optional(odm.Keyword(store=True, default=DEFAULT_SERVICE_REJECTS))

    category = odm.Keyword(store=True, default="Static Analysis", copyto="__text__")
    config = odm.Mapping(odm.Any(), default={}, index=False, store=False)
    description = odm.Text(store=True, default="NA", copyto="__text__")
    default_result_classification = odm.ClassificationString(default=Classification.UNRESTRICTED)
    enabled = odm.Boolean(store=True, default=False)
    is_external = odm.Boolean(default=False)
    licence_count = odm.Integer(default=0)

    name = odm.Keyword(store=True, copyto="__text__")
    version = odm.Keyword(store=True)

    # Should the result cache be disabled for this service
    disable_cache = odm.Boolean(default=False)

    stage = odm.Keyword(store=True, default="CORE", copyto="__text__")
    submission_params: SubmissionParams = odm.List(odm.Compound(SubmissionParams), index=False, default=[])
    timeout = odm.Integer(default=60)

    docker_config: DockerConfig = odm.Compound(DockerConfig)
    dependencies = odm.List(odm.Compound(DockerConfig), default=[])    # List of other required Docker container(s)

    update_config: UpdateConfig = odm.Optional(odm.Compound(UpdateConfig))
