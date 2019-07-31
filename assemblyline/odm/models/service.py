from assemblyline import odm
from assemblyline.common.constants import DEFAULT_SERVICE_ACCEPTS, DEFAULT_SERVICE_REJECTS


@odm.model(index=False, store=False)
class EnvironmentVariable(odm.Model):
    name = odm.Keyword()
    value = odm.Keyword()


@odm.model(index=False, store=False)
class DockerConfig(odm.Model):
    image = odm.Keyword()                                 # Complete name of the Docker image with tag
    command = odm.Optional(odm.Keyword())
    environment = odm.List(odm.Compound(EnvironmentVariable), default=[])
    network = odm.List(odm.Keyword(), default=[])         # Network access rules


@odm.model(index=False, store=False)
class UpdateSource(odm.Model):
    uri = odm.Keyword()
    # ETC.


@odm.model(index=False, store=False)
class UpdateConfig(odm.Model):
    method = odm.Enum(values=['run', 'build'])                    # Are we going to run a container, or build a new container?
    sources = odm.List(odm.Compound(UpdateSource))                # Generic external resources we need
    update_interval_seconds = odm.Integer()                       # Update check interval in seconds
    run_options = odm.Optional(odm.Compound(DockerConfig))        # If we are going to run a container, which one?
    # build_options = odm.Optional(odm.Compound(DockerfileConfig))  # If we are going to build a container, how?


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
    config = odm.Mapping(odm.Any(), default={})
    cpu_cores = odm.Float(default=1.0)
    description = odm.Text(store=True, default="NA", copyto="__text__")
    enabled = odm.Boolean(store=True, default=False)
    install_by_default = odm.Boolean(default=False)
    is_external = odm.Boolean(default=False)
    licence_count = odm.Integer(default=0)

    name = odm.Keyword(store=True, copyto="__text__")
    version = odm.Keyword(store=True)

    ram_mb = odm.Integer(default=1024)

    # Should the result cache be disabled for this service
    disable_cache = odm.Boolean(default=False)

    stage = odm.Keyword(store=True, default="CORE", copyto="__text__")
    submission_params: SubmissionParams = odm.List(odm.Compound(SubmissionParams), index=False, default=[])
    supported_platforms = odm.List(odm.Enum(values=["windows", "linux"]), default=["linux"])
    timeout = odm.Integer(default=60)

    docker_config: DockerConfig = odm.Compound(DockerConfig)
    dependencies = odm.List(odm.Compound(DockerConfig), default=[])    # List of other required Docker container(s)

    update_config: UpdateConfig = odm.Optional(odm.Compound(UpdateConfig))
