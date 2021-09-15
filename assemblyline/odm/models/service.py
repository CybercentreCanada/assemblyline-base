from __future__ import annotations
from typing import Optional as Opt

from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.constants import DEFAULT_SERVICE_ACCEPTS, DEFAULT_SERVICE_REJECTS

Classification = forge.get_classification()


@odm.model(index=False, store=False)
class EnvironmentVariable(odm.Model):
    name: str = odm.Keyword()
    value: str = odm.Keyword()


@odm.model(index=False, store=False)
class DockerConfig(odm.Model):
    allow_internet_access: bool = odm.Boolean(default=False)
    command: Opt[list[str]] = odm.Optional(odm.List(odm.Keyword()))
    cpu_cores: float = odm.Float(default=1.0)
    environment: list[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[])
    image: str = odm.Keyword()                       # Complete name of the Docker image with tag, may include registry
    registry_username: Opt[str] = odm.Optional(odm.Keyword())  # The username to use when pulling the image
    registry_password: Opt[str] = odm.Optional(odm.Keyword())  # The password or token to use when pulling the image
    registry_type: str = odm.Enum(values=["docker", "harbor"], default='docker')  # The type of registry (Docker, Harbor)
    ports: list[str] = odm.List(odm.Keyword(), default=[])
    ram_mb: int = odm.Integer(default=512)
    ram_mb_min: int = odm.Integer(default=128)


@odm.model(index=False, store=False)
class PersistentVolume(odm.Model):
    mount_path = odm.Keyword()  # Path into the container to mount volume
    capacity = odm.Keyword()  # Bytes
    storage_class = odm.Keyword()


@odm.model(index=False, store=False)
class DependencyConfig(odm.Model):
    container: DockerConfig = odm.Compound(DockerConfig)
    volumes = odm.Mapping(odm.Compound(PersistentVolume), default={})
    run_as_core: bool = odm.Boolean(default=False)


@odm.model(index=False, store=False)
class UpdateSource(odm.Model):
    name: str = odm.Keyword()
    password: Opt[str] = odm.Optional(odm.Keyword(default=""))
    pattern: Opt[str] = odm.Optional(odm.Keyword(default=""))
    private_key: Opt[str] = odm.Optional(odm.Keyword(default=""))
    ca_cert: Opt[str] = odm.Optional(odm.Keyword(default=""))
    ssl_ignore_errors: bool = odm.Boolean(default=False)
    proxy: Opt[str] = odm.Optional(odm.Keyword(default=""))
    uri: str = odm.Keyword()
    username: Opt[str] = odm.Optional(odm.Keyword(default=""))
    headers: list[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[])
    default_classification = odm.Classification(default=Classification.UNRESTRICTED)


@odm.model(index=False, store=False)
class UpdateConfig(odm.Model):
    # build_options = odm.Optional(odm.Compound(DockerfileConfig))  # If we are going to build a container, how?
    generates_signatures = odm.Boolean(index=True, default=False)
    method = odm.Enum(values=['run', 'build'])                    # Are we going to run or build a container?
    run_options = odm.Optional(odm.Compound(DockerConfig))        # If we are going to run a container, which one?
    sources: list[UpdateSource] = odm.List(odm.Compound(UpdateSource), default=[])    # Generic external resources we need
    update_interval_seconds: int = odm.Integer()                       # Update check interval in seconds
    wait_for_update: bool = odm.Boolean(default=False)


@odm.model(index=False, store=False)
class SubmissionParams(odm.Model):
    default = odm.Any()
    name = odm.Keyword()
    type = odm.Enum(values=['str', 'int', 'list', 'bool'])
    value = odm.Any()
    list = odm.Optional(odm.Any())
    hide = odm.Boolean(default=False)


@odm.model(index=True, store=False)
class Service(odm.Model):
    # Regexes applied to assemblyline style file type string
    accepts = odm.Keyword(store=True, default=DEFAULT_SERVICE_ACCEPTS)
    rejects = odm.Optional(odm.Keyword(store=True, default=DEFAULT_SERVICE_REJECTS))

    category = odm.Keyword(store=True, default="Static Analysis", copyto="__text__")
    config = odm.Mapping(odm.Any(), default={}, index=False, store=False)
    description = odm.Text(store=True, default="NA", copyto="__text__")
    default_result_classification = odm.ClassificationString(default=Classification.UNRESTRICTED)
    enabled: bool = odm.Boolean(store=True, default=False)
    is_external: bool = odm.Boolean(default=False)
    licence_count: int = odm.Integer(default=0)

    name: str = odm.Keyword(store=True, copyto="__text__")
    version = odm.Keyword(store=True)

    # Should the result cache be disabled for this service
    disable_cache = odm.Boolean(default=False)

    stage = odm.Keyword(store=True, default="CORE", copyto="__text__")
    submission_params: SubmissionParams = odm.List(odm.Compound(SubmissionParams), index=False, default=[])
    timeout: int = odm.Integer(default=60)

    docker_config: DockerConfig = odm.Compound(DockerConfig)
    dependencies: dict[str, DependencyConfig] = odm.Mapping(odm.Compound(DependencyConfig), default={})

    update_channel: str = odm.Enum(values=["stable", "rc", "beta", "dev"], default='stable')
    update_config: UpdateConfig = odm.Optional(odm.Compound(UpdateConfig))
