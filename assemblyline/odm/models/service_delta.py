from assemblyline import odm
from assemblyline.odm.models.service import SIGNATURE_DELIMITERS

REF_DOCKER_CONFIG = "Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)"
REF_ENVVAR = "Refer to:<br>[Service - Enviroment Variable](../service/#environmentvariable)"


REF_DEPENDENCY_CONFIG = "Refer to:<br>[Service - DependencyConfig](../service/#dependencyconfig)"
REF_DOCKER_CONFIG = "Refer to:<br>[Service - DockerConfig](../service/#dockerconfig)"
REF_ENVVAR = "Refer to:<br>[Service - Enviroment Variable](../service/#environmentvariable)"
REF_PV = "Refer to:<br>[Service - PeristentVolume](../service/#persistentvolume)"
REF_SERVICE = "Refer to:<br>[Service](../service/#service)"
REF_SUBMISSION_PARAMS = "Refer to:<br>[Service - SubmissionParams](../service/#submissionparams)"
REF_UPDATE_CONFIG = "Refer to:<br>[Service - UpdateConfig](../service/#updateconfig)"
REF_UPDATE_SOURCE = "Refer to:<br>[Service - UpdateSource](../service/#updatesource)"


@odm.model(index=False, store=False)
class EnvironmentVariable(odm.Model):
    name: str = odm.Keyword(description=REF_ENVVAR)
    value: str = odm.Keyword(description=REF_ENVVAR)


@odm.model(index=False, store=False, description="Docker Configuration Delta")
class DockerConfigDelta(odm.Model):
    allow_internet_access = odm.Optional(odm.Boolean(), description=REF_DOCKER_CONFIG)
    command = odm.Optional(odm.List(odm.Keyword()), description=REF_DOCKER_CONFIG)
    cpu_cores = odm.Optional(odm.Float(), description=REF_DOCKER_CONFIG)
    environment = odm.Optional(odm.List(odm.Compound(EnvironmentVariable)), description=REF_DOCKER_CONFIG)
    image = odm.Optional(odm.Keyword(), description=REF_DOCKER_CONFIG)
    registry_username = odm.Optional(odm.Keyword(default=""), description=REF_DOCKER_CONFIG)
    registry_password = odm.Optional(odm.Keyword(default=""), description=REF_DOCKER_CONFIG)
    registry_type = odm.Optional(odm.Enum(values=["docker", "harbor"]), description=REF_DOCKER_CONFIG)
    ports = odm.Optional(odm.List(odm.Keyword()), description=REF_DOCKER_CONFIG)
    ram_mb = odm.Optional(odm.Integer(), description=REF_DOCKER_CONFIG)
    ram_mb_min = odm.Optional(odm.Integer(), description=REF_DOCKER_CONFIG)
    service_account = odm.optional(odm.keyword(description=REF_DOCKER_CONFIG))


@odm.model(index=False, store=False)
class UpdateSourceDelta(odm.Model):
    name = odm.Optional(odm.Keyword(), description=REF_UPDATE_SOURCE)
    password = odm.Optional(odm.Keyword(default=""), description=REF_UPDATE_SOURCE)
    pattern = odm.Optional(odm.Keyword(default=""), description=REF_UPDATE_SOURCE)
    private_key = odm.Keyword(default="", description=REF_UPDATE_SOURCE)
    ca_cert = odm.Optional(odm.Keyword(default=""), description=REF_UPDATE_SOURCE)
    ssl_ignore_errors = odm.Boolean(default=False, description=REF_UPDATE_SOURCE)
    proxy = odm.Optional(odm.Keyword(default=""), description=REF_UPDATE_SOURCE)
    uri = odm.Optional(odm.Keyword(), description=REF_UPDATE_SOURCE)
    username = odm.Optional(odm.Keyword(default=""), description=REF_UPDATE_SOURCE)
    headers = odm.Optional(odm.List(odm.Compound(EnvironmentVariable)), description=REF_UPDATE_SOURCE)
    default_classification = odm.Optional(odm.Classification(), description=REF_UPDATE_SOURCE)
    git_branch = odm.Optional(odm.Keyword(default=""), description=REF_UPDATE_SOURCE)


@ odm.model(index=False, store=False)
class PersistentVolumeDelta(odm.Model):
    mount_path = odm.Optional(odm.Keyword(), description=REF_PV)
    capacity = odm.Optional(odm.Keyword(), description=REF_PV)
    storage_class = odm.Optional(odm.Keyword(), description=REF_PV)
    access_mode = odm.Optional(odm.Enum(values=['ReadWriteOnce', 'ReadWriteMany']), description=REF_PV)


@ odm.model(index=False, store=False)
class DependencyConfigDelta(odm.Model):
    container = odm.Optional(odm.Compound(DockerConfigDelta), description=REF_DEPENDENCY_CONFIG)
    volumes = odm.Mapping(odm.Compound(PersistentVolumeDelta), default={}, description=REF_DEPENDENCY_CONFIG)
    run_as_core: bool = odm.Optional(odm.Boolean(), description=REF_DEPENDENCY_CONFIG)


@ odm.model(index=False, store=False)
class UpdateConfigDelta(odm.Model):
    generates_signatures = odm.Optional(odm.Boolean(), index=True, description=REF_UPDATE_CONFIG)
    sources = odm.Optional(odm.List(odm.Compound(UpdateSourceDelta)), description=REF_UPDATE_CONFIG)
    update_interval_seconds = odm.Optional(odm.Integer(), description=REF_UPDATE_CONFIG)
    wait_for_update = odm.Optional(odm.Boolean(), description=REF_UPDATE_CONFIG)
    signature_delimiter = odm.Optional(odm.Enum(values=SIGNATURE_DELIMITERS.keys()), description=REF_UPDATE_CONFIG)
    custom_delimiter = odm.Optional(odm.Keyword(), description=REF_UPDATE_CONFIG)


@ odm.model(index=False, store=False)
class SubmissionParamsDelta(odm.Model):
    default = odm.Optional(odm.Any(), description=REF_SUBMISSION_PARAMS)
    name = odm.Optional(odm.Keyword(), description=REF_SUBMISSION_PARAMS)
    type = odm.Optional(odm.Enum(values=['str', 'int', 'list', 'bool']), description=REF_SUBMISSION_PARAMS)
    value = odm.Optional(odm.Any(), description=REF_SUBMISSION_PARAMS)
    list = odm.Optional(odm.Any(), description=REF_SUBMISSION_PARAMS)
    hide = odm.Optional(odm.Boolean(), description=REF_SUBMISSION_PARAMS)


@ odm.model(index=True, store=False, description="Service Delta relative to Initial Service Configuration")
class ServiceDelta(odm.Model):
    accepts = odm.Optional(odm.Keyword(), store=True, description=REF_SERVICE)
    rejects = odm.Optional(odm.Keyword(), store=True, description=REF_SERVICE)
    category = odm.Optional(odm.Keyword(), store=True, copyto="__text__", description=REF_SERVICE)
    config = odm.Optional(odm.Mapping(odm.Any()), index=False, description=REF_SERVICE)
    description = odm.Optional(odm.Text(), store=True, copyto="__text__", description=REF_SERVICE)
    default_result_classification = odm.Optional(odm.ClassificationString(), description=REF_SERVICE)
    enabled = odm.Optional(odm.Boolean(), store=True, description=REF_SERVICE)
    is_external = odm.Optional(odm.Boolean(), description=REF_SERVICE)
    licence_count = odm.Optional(odm.Integer(), description=REF_SERVICE)
    max_queue_length = odm.Optional(odm.Integer(), description=REF_SERVICE)

    uses_tags: bool = odm.Optional(odm.Boolean(), description=REF_SERVICE)
    uses_tag_scores: bool = odm.Optional(odm.Boolean(), description=REF_SERVICE)
    uses_temp_submission_data: bool = odm.Optional(odm.Boolean(), description=REF_SERVICE)
    uses_metadata: bool = odm.Optional(odm.Boolean(), description=REF_SERVICE)

    name = odm.Optional(odm.Keyword(), store=True, copyto="__text__", description=REF_SERVICE)
    version = odm.Keyword(store=True, description=REF_SERVICE)

    privileged = odm.Optional(odm.Boolean(), description=REF_SERVICE)
    disable_cache = odm.Optional(odm.Boolean(), description=REF_SERVICE)

    stage = odm.Optional(odm.Keyword(), store=True, copyto="__text__", description=REF_SERVICE)
    submission_params = odm.Optional(odm.List(odm.Compound(SubmissionParamsDelta)), index=False,
                                     description=REF_SERVICE)
    timeout = odm.Optional(odm.Integer(), description=REF_SERVICE)

    docker_config: DockerConfigDelta = odm.Optional(odm.Compound(DockerConfigDelta), description=REF_SERVICE)
    dependencies: DependencyConfigDelta = odm.Mapping(odm.Compound(DependencyConfigDelta), default={},
                                                      description=REF_SERVICE)

    update_channel = odm.Optional(odm.Enum(values=["stable", "rc", "beta", "dev"]), description=REF_SERVICE)
    update_config: UpdateConfigDelta = odm.Optional(odm.Compound(UpdateConfigDelta), description=REF_SERVICE)
