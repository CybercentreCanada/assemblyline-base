from __future__ import annotations
from typing import Optional as Opt

from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.constants import DEFAULT_SERVICE_ACCEPTS, DEFAULT_SERVICE_REJECTS

Classification = forge.get_classification()

SIGNATURE_DELIMITERS = {
    'new_line': '\n',
    'double_new_line': '\n\n',
    'pipe': '|',
    'comma': ',',
    'space': ' ',
    'none': '',
    'file': '',
    'custom': ''
}


@odm.model(index=False, store=False, description="Environment Variable Model")
class EnvironmentVariable(odm.Model):
    name: str = odm.Keyword(description="Name of Environment Variable")
    value: str = odm.Keyword(description="Value of Environment Variable")


@odm.model(index=False, store=False, description="Docker Container Configuration")
class DockerConfig(odm.Model):
    allow_internet_access: bool = odm.Boolean(default=False, description="Does the container have internet-access?")
    command: Opt[list[str]] = odm.Optional(odm.List(odm.Keyword()),
                                           description="Command to run when container starts up.")
    cpu_cores: float = odm.Float(default=1.0, description="CPU allocation")
    environment: list[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[],
                                                      description="Additional environemnt variables for the container")
    image: str = odm.Keyword(description="Complete name of the Docker image with tag, may include registry")
    registry_username: Opt[str] = odm.Optional(odm.Keyword(), description="The username to use when pulling the image")
    registry_password: Opt[str] = odm.Optional(odm.Keyword(),
                                               description="The password or token to use when pulling the image")
    registry_type: str = odm.Enum(values=["docker", "harbor"], default='docker',
                                  description="The type of container registry")
    ports: list[str] = odm.List(odm.Keyword(), default=[], description="What ports of container to expose?")
    ram_mb: int = odm.Integer(default=512, description="Container RAM limit")
    ram_mb_min: int = odm.Integer(default=128, description="Container RAM request")
    service_account = odm.optional(odm.keyword(description="Service account to use for pods in kubernetes"))


@ odm.model(index=False, store=False, description="Container's Persistent Volume Configuration")
class PersistentVolume(odm.Model):
    mount_path = odm.Keyword(description="Path into the container to mount volume")
    capacity = odm.Keyword(description="The amount of storage allocated for volume")
    storage_class = odm.Keyword(description="Storage class used to create volume")
    access_mode = odm.Enum(default='ReadWriteOnce', values=['ReadWriteOnce', 'ReadWriteMany'],
                           description="Access mode for volume")


@ odm.model(index=False, store=False, description="Container's Dependency Configuration")
class DependencyConfig(odm.Model):
    container: DockerConfig = odm.Compound(DockerConfig, description="Docker container configuration for dependency")
    volumes = odm.Mapping(odm.Compound(PersistentVolume), default={}, description="Volume configuration for dependency")
    run_as_core: bool = odm.Boolean(default=False, description="Should this dependency run as other core components?")


@ odm.model(index=False, store=False, description="Update Source Configuration")
class UpdateSource(odm.Model):
    name: str = odm.Keyword(description="Name of source")
    password: Opt[str] = odm.Optional(odm.Keyword(default=""), description="Password used to authenticate with source")
    pattern: Opt[str] = odm.Optional(odm.Keyword(default=""),
                                     description="Pattern used to find files of interest from source")
    private_key: Opt[str] = odm.Optional(odm.Keyword(default=""),
                                         description="Private key used to authenticate with source")
    ca_cert: Opt[str] = odm.Optional(odm.Keyword(default=""), description="CA cert for source")
    ssl_ignore_errors: bool = odm.Boolean(default=False, description="Ignore SSL errors when reaching out to source?")
    proxy: Opt[str] = odm.Optional(odm.Keyword(default=""), description="Proxy server for source")
    uri: str = odm.Keyword(description="URI to source")
    username: Opt[str] = odm.Optional(odm.Keyword(default=""), description="Username used to authenticate with source")
    headers: list[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[], description="Headers")
    default_classification = odm.Classification(
        default=Classification.UNRESTRICTED,
        description="Default classification used in absence of one defined in files from source")
    git_branch: str = odm.Optional(odm.Keyword(default=""), description="Branch to checkout from Git repository.")


@ odm.model(index=False, store=False, description="Update Configuration for Signatures")
class UpdateConfig(odm.Model):
    generates_signatures = odm.Boolean(index=True, default=False, description="Does the updater produce signatures?")
    sources = odm.List(odm.Compound(UpdateSource), default=[], description="List of external sources")
    update_interval_seconds = odm.Integer(description="Update check interval, in seconds")
    wait_for_update = odm.Boolean(default=False, description="Should the service wait for updates first?")
    signature_delimiter = odm.Enum(values=SIGNATURE_DELIMITERS.keys(),
                                   default="double_new_line",
                                   description="Delimiter used when given a list of signatures")
    custom_delimiter = odm.Optional(odm.Keyword(), description="Custom delimiter definition")


@ odm.model(index=False, store=False, description="Submission Parameters for Service")
class SubmissionParams(odm.Model):
    default = odm.Any(description="Default value (must match value in `value` field)")
    name = odm.Keyword(description="Name of parameter")
    type = odm.Enum(values=['str', 'int', 'list', 'bool'], description="Type of parameter")
    value = odm.Any(description="Default value (must match value in `default` field)")
    list = odm.Optional(odm.Any(), description="List of values if `type: list`")
    hide = odm.Boolean(default=False, description="Should this parameter be hidden?")


@ odm.model(index=True, store=False, description="Service Configuration")
class Service(odm.Model):
    # Regexes applied to assemblyline style file type string
    accepts = odm.Keyword(store=True, default=DEFAULT_SERVICE_ACCEPTS,
                          description="Regex to accept files as identified by Assemblyline")
    rejects = odm.Optional(odm.Keyword(store=True, default=DEFAULT_SERVICE_REJECTS),
                           description="Regex to reject files as identified by Assemblyline")

    category = odm.Keyword(store=True, default="Static Analysis", copyto="__text__",
                           description="Which category does this service belong to?")
    config = odm.Mapping(odm.Any(), default={}, index=False, store=False, description="Service Configuration")
    description = odm.Text(store=True, default="NA", copyto="__text__", description="Description of service")
    default_result_classification = odm.ClassificationString(
        default=Classification.UNRESTRICTED, description="Default classification assigned to service results")
    enabled: bool = odm.Boolean(store=True, default=False, description="Is the service enabled (by default)?")
    is_external: bool = odm.Boolean(
        default=False, description="Does this service perform analysis outside of Assemblyline?")
    licence_count: int = odm.Integer(default=0, description="How many licences is the service allowed to use?")
    max_queue_length: int = odm.Integer(
        default=0,
        description="If more than this many jobs are queued for this service drop those over this limit. 0 is unlimited.")

    uses_tags: bool = odm.Boolean(
        default=False, description="Does this service use tags from other services for analysis?")
    uses_tag_scores: bool = odm.Boolean(
        default=False, description="Does this service use scores of tags from other services for analysis?")
    uses_temp_submission_data: bool = odm.Boolean(
        default=False, description="Does this service use temp data from other services for analysis?")
    uses_metadata: bool = odm.Boolean(
        default=False, description="Does this service use submission metadata for analysis?")

    name: str = odm.Keyword(store=True, copyto="__text__", description="Name of service")
    version = odm.Keyword(store=True, description="Version of service")

    privileged = odm.Boolean(
        default=False,
        description="Should the service be able to talk to core infrastructure or just service-server for tasking?")
    disable_cache = odm.Boolean(default=False, description="Should the result cache be disabled for this service?")

    stage = odm.Keyword(store=True, default="CORE", copyto="__text__",
                        description="Which execution stage does this service run in?")
    submission_params: SubmissionParams = odm.List(
        odm.Compound(SubmissionParams),
        index=False, default=[],
        description="Submission parameters of service")
    timeout: int = odm.Integer(default=60, description="Service task timeout, in seconds")

    docker_config: DockerConfig = odm.Compound(DockerConfig, description="Docker configuration for service")
    dependencies: dict[str, DependencyConfig] = odm.Mapping(odm.Compound(
        DependencyConfig), default={}, description="Dependency configuration for service")

    update_channel: str = odm.Enum(
        values=["stable", "rc", "beta", "dev"],
        default='stable', description="What channel to watch for service updates?")
    update_config: UpdateConfig = odm.Optional(
        odm.Compound(UpdateConfig),
        description="Update configuration for fetching external resources")
