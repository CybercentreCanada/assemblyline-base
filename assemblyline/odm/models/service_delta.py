from assemblyline import odm


@odm.model(index=False, store=False)
class EnvironmentVariable(odm.Model):
    name = odm.Keyword()
    value = odm.Keyword()


@odm.model(index=False, store=False)
class DockerConfigDelta(odm.Model):
    allow_internet_access = odm.Optional(odm.Boolean())
    command = odm.Optional(odm.List(odm.Keyword()))
    cpu_cores = odm.Optional(odm.Float())
    environment = odm.Optional(odm.List(odm.Compound(EnvironmentVariable)))
    image = odm.Optional(odm.Keyword())  # The docker image and tag, optionally including registry in the normal way
    registry_username = odm.Optional(odm.Keyword())  # The username to use when pulling the image
    registry_password = odm.Optional(odm.Keyword())  # The password or token to use when pulling the image
    registry_type = odm.Optional(odm.Enum(values=["docker", "harbor"]))  # The type of registry (Docker, Harbor)
    ports = odm.Optional(odm.List(odm.Keyword()))
    ram_mb = odm.Optional(odm.Integer())
    ram_mb_min = odm.Optional(odm.Integer())


@odm.model(index=False, store=False)
class UpdateSourceDelta(odm.Model):
    headers = odm.Optional(odm.List(odm.Compound(EnvironmentVariable)))
    name = odm.Optional(odm.Keyword())
    password = odm.Optional(odm.Keyword(default=""))
    pattern = odm.Optional(odm.Keyword(default=""))
    private_key = odm.Optional(odm.Keyword(default=""))
    ca_cert = odm.Optional(odm.Keyword(default=""))
    ssl_ignore_errors = odm.Boolean(default=False)
    proxy = odm.Optional(odm.Keyword(default=""))
    uri = odm.Optional(odm.Keyword())
    username = odm.Optional(odm.Keyword(default=""))
    default_classification = odm.Optional(odm.Classification())


@odm.model(index=False, store=False)
class PersistentVolumeDelta(odm.Model):
    mount_path = odm.Optional(odm.Keyword())
    capacity = odm.Optional(odm.Keyword())
    storage_class = odm.Optional(odm.Keyword())


@odm.model(index=False, store=False)
class DependencyConfigDelta(odm.Model):
    container = odm.Optional(odm.Compound(DockerConfigDelta))
    volumes = odm.Mapping(odm.Compound(PersistentVolumeDelta), default={})
    run_as_core: bool = odm.Optional(odm.Boolean())


@odm.model(index=False, store=False)
class UpdateConfigDelta(odm.Model):
    generates_signatures = odm.Optional(odm.Boolean(), index=True)
    sources = odm.Optional(odm.List(odm.Compound(UpdateSourceDelta)))
    update_interval_seconds = odm.Optional(odm.Integer())
    wait_for_update = odm.Optional(odm.Boolean())


@odm.model(index=False, store=False)
class SubmissionParamsDelta(odm.Model):
    default = odm.Optional(odm.Any())
    name = odm.Optional(odm.Keyword())
    type = odm.Optional(odm.Enum(values=['str', 'int', 'list', 'bool']))
    value = odm.Optional(odm.Any())
    list = odm.Optional(odm.Any())
    hide = odm.Optional(odm.Any())


@odm.model(index=True, store=False)
class ServiceDelta(odm.Model):
    accepts = odm.Optional(odm.Keyword(), store=True)
    rejects = odm.Optional(odm.Keyword(), store=True)

    category = odm.Optional(odm.Keyword(), store=True, copyto="__text__")
    config = odm.Optional(odm.Mapping(odm.Any()), index=False)
    description = odm.Optional(odm.Text(), store=True, copyto="__text__")
    default_result_classification = odm.Optional(odm.ClassificationString())
    enabled = odm.Optional(odm.Boolean(), store=True)
    is_external = odm.Optional(odm.Boolean())
    licence_count = odm.Optional(odm.Integer())

    name = odm.Optional(odm.Keyword(), store=True, copyto="__text__")
    version = odm.Keyword(store=True)

    disable_cache = odm.Optional(odm.Boolean())

    stage = odm.Optional(odm.Keyword(), store=True, copyto="__text__")
    submission_params = odm.Optional(odm.List(odm.Compound(SubmissionParamsDelta)), index=False)
    timeout = odm.Optional(odm.Integer())

    docker_config: DockerConfigDelta = odm.Optional(odm.Compound(DockerConfigDelta))
    dependencies: DependencyConfigDelta = odm.Mapping(odm.Compound(DependencyConfigDelta), default={})

    update_channel = odm.Optional(odm.Enum(values=["stable", "rc", "beta", "dev"]))
    update_config: UpdateConfigDelta = odm.Optional(odm.Compound(UpdateConfigDelta))
