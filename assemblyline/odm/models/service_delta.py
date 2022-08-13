from assemblyline import odm
from assemblyline.odm.models.service import SIGNATURE_DELIMITERS


@odm.model(index=False, store=False)
class EnvironmentVariable(odm.Model):
    name: str = odm.Keyword(description="Refer to:<br>[Service - Enviroment Variable](../service/#environmentvariable)")
    value: str = odm.Keyword(
        description="Refer to:<br>[Service - Enviroment Variable](../service/#environmentvariable)")


@odm.model(index=False, store=False, description="Docker Configuration Delta")
class DockerConfigDelta(odm.Model):
    allow_internet_access = odm.Optional(
        odm.Boolean(),
        description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")
    command = odm.Optional(
        odm.List(odm.Keyword()),
        description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")
    cpu_cores = odm.Optional(odm.Float(), description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")
    environment = odm.Optional(
        odm.List(odm.Compound(EnvironmentVariable)),
        description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")
    image = odm.Optional(odm.Keyword())  # The docker image and tag, optionally including registry in the normal way
    registry_username = odm.Optional(odm.Keyword())  # The username to use when pulling the image
    registry_password = odm.Optional(odm.Keyword())  # The password or token to use when pulling the image
    # The type of registry (Docker, Harbor, description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")
    registry_type = odm.Optional(odm.Enum(values=["docker", "harbor"]))
    ports = odm.Optional(
        odm.List(odm.Keyword()),
        description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")
    ram_mb = odm.Optional(odm.Integer(), description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")
    ram_mb_min = odm.Optional(
        odm.Integer(),
        description="Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)")


@odm.model(index=False, store=False)
class UpdateSourceDelta(odm.Model):
    name = odm.Optional(odm.Keyword(), description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    password = odm.Optional(
        odm.Keyword(default=""),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    pattern = odm.Optional(
        odm.Keyword(default=""),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    private_key = odm.Optional(
        odm.Keyword(default=""),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    ca_cert = odm.Optional(
        odm.Keyword(default=""),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    ssl_ignore_errors = odm.Boolean(
        default=False, description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    proxy = odm.Optional(
        odm.Keyword(default=""),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    uri = odm.Optional(odm.Keyword(), description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    username = odm.Optional(
        odm.Keyword(default=""),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    headers = odm.Optional(
        odm.List(odm.Compound(EnvironmentVariable)),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    default_classification = odm.Optional(
        odm.Classification(),
        description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")
    git_branch = odm.Optional(odm.Keyword(default=""), description="Refer to:<br>[Service - UpdateSource](../service/#updatesource)")



@odm.model(index=False, store=False)
class PersistentVolumeDelta(odm.Model):
    mount_path = odm.Optional(
        odm.Keyword(),
        description="Refer to:<br>[Service - PeristentVolume](../service/#persistentvolume)")
    capacity = odm.Optional(
        odm.Keyword(),
        description="Refer to:<br>[Service - PeristentVolume](../service/#persistentvolume)")
    storage_class = odm.Optional(
        odm.Keyword(),
        description="Refer to:<br>[Service - PeristentVolume](../service/#persistentvolume)")


@odm.model(index=False, store=False)
class DependencyConfigDelta(odm.Model):
    container = odm.Optional(
        odm.Compound(DockerConfigDelta),
        description="Refer to:<br>[Service - DependencyConfig](../service/#dependencyconfig)")
    volumes = odm.Mapping(odm.Compound(PersistentVolumeDelta), default={},
                          description="Refer to:<br>[Service - DependencyConfig](../service/#dependencyconfig)")
    run_as_core: bool = odm.Optional(
        odm.Boolean(),
        description="Refer to:<br>[Service - DependencyConfig](../service/#dependencyconfig)")


@odm.model(index=False, store=False)
class UpdateConfigDelta(odm.Model):
    generates_signatures = odm.Optional(
        odm.Boolean(),
        index=True, description="Refer to:<br>[Service - UpdateConfig](../service/#updateconfig)")
    sources = odm.Optional(
        odm.List(odm.Compound(UpdateSourceDelta)),
        description="Refer to:<br>[Service - UpdateConfig](../service/#updateconfig)")
    update_interval_seconds = odm.Optional(
        odm.Integer(),
        description="Refer to:<br>[Service - UpdateConfig](../service/#updateconfig)")
    wait_for_update = odm.Optional(
        odm.Boolean(),
        description="Refer to:<br>[Service - UpdateConfig](../service/#updateconfig)")
    signature_delimiter = odm.Optional(
        odm.Enum(values=SIGNATURE_DELIMITERS.keys()),
        description="Refer to:<br>[Service - UpdateConfig](../service/#updateconfig)")
    custom_delimiter = odm.Optional(
        odm.Keyword(),
        description="Refer to:<br>[Service - UpdateConfig](../service/#updateconfig)")


@odm.model(index=False, store=False)
class SubmissionParamsDelta(odm.Model):
    default = odm.Optional(
        odm.Any(),
        description="Refer to:<br>[Service - SubmissionParams](../service/#submissionparams)")
    name = odm.Optional(
        odm.Keyword(),
        description="Refer to:<br>[Service - SubmissionParams](../service/#submissionparams)")
    type = odm.Optional(
        odm.Enum(values=['str', 'int', 'list', 'bool']),
        description="Refer to:<br>[Service - SubmissionParams](../service/#submissionparams)")
    value = odm.Optional(
        odm.Any(),
        description="Refer to:<br>[Service - SubmissionParams](../service/#submissionparams)")
    list = odm.Optional(
        odm.Any(),
        description="Refer to:<br>[Service - SubmissionParams](../service/#submissionparams)")
    hide = odm.Optional(
        odm.Boolean(),
        description="Refer to:<br>[Service - SubmissionParams](../service/#submissionparams)")


@odm.model(index=True, store=False, description="Service Delta relative to Initial Service Configuration")
class ServiceDelta(odm.Model):
    accepts = odm.Optional(odm.Keyword(), store=True, description="Refer to:<br>[Service](../service/#service)")
    rejects = odm.Optional(odm.Keyword(), store=True, description="Refer to:<br>[Service](../service/#service)")

    category = odm.Optional(odm.Keyword(), store=True, copyto="__text__",
                            description="Refer to:<br>[Service](../service/#service)")
    config = odm.Optional(odm.Mapping(odm.Any()), index=False,
                          description="Refer to:<br>[Service](../service/#service)")
    description = odm.Optional(odm.Text(), store=True, copyto="__text__",
                               description="Refer to:<br>[Service](../service/#service)")
    default_result_classification = odm.Optional(
        odm.ClassificationString(),
        description="Refer to:<br>[Service](../service/#service)")
    enabled = odm.Optional(odm.Boolean(), store=True, description="Refer to:<br>[Service](../service/#service)")
    is_external = odm.Optional(odm.Boolean(), description="Refer to:<br>[Service](../service/#service)")
    licence_count = odm.Optional(odm.Integer(), description="Refer to:<br>[Service](../service/#service)")
    max_queue_length = odm.Optional(odm.Integer(), description="Refer to:<br>[Service](../service/#service)")

    uses_tags: bool = odm.Optional(odm.Boolean(), description="Refer to:<br>[Service](../service/#service)")
    uses_tag_scores: bool = odm.Optional(odm.Boolean(), description="Refer to:<br>[Service](../service/#service)")
    uses_temp_submission_data: bool = odm.Optional(
        odm.Boolean(), description="Refer to:<br>[Service](../service/#service)")
    uses_metadata: bool = odm.Optional(odm.Boolean(), description="Refer to:<br>[Service](../service/#service)")

    name = odm.Optional(odm.Keyword(), store=True, copyto="__text__",
                        description="Refer to:<br>[Service](../service/#service)")
    version = odm.Keyword(store=True, description="Refer to:<br>[Service](../service/#service)")

    privileged = odm.Optional(odm.Boolean(), description="Refer to:<br>[Service](../service/#service)")
    disable_cache = odm.Optional(odm.Boolean(), description="Refer to:<br>[Service](../service/#service)")

    stage = odm.Optional(odm.Keyword(), store=True, copyto="__text__",
                         description="Refer to:<br>[Service](../service/#service)")
    submission_params = odm.Optional(
        odm.List(odm.Compound(SubmissionParamsDelta)),
        index=False, description="Refer to:<br>[Service](../service/#service)")
    timeout = odm.Optional(odm.Integer(), description="Refer to:<br>[Service](../service/#service)")

    docker_config: DockerConfigDelta = odm.Optional(
        odm.Compound(DockerConfigDelta),
        description="Refer to:<br>[Service](../service/#service)")
    dependencies: DependencyConfigDelta = odm.Mapping(
        odm.Compound(DependencyConfigDelta),
        default={},
        description="Refer to:<br>[Service](../service/#service)")

    update_channel = odm.Optional(
        odm.Enum(values=["stable", "rc", "beta", "dev"]),
        description="Refer to:<br>[Service](../service/#service)")
    update_config: UpdateConfigDelta = odm.Optional(
        odm.Compound(UpdateConfigDelta),
        description="Refer to:<br>[Service](../service/#service)")
