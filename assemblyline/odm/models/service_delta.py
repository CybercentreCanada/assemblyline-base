from assemblyline import odm


@odm.model(index=False, store=False)
class EnvironmentVariableDelta(odm.Model):
    name = odm.Keyword()
    value = odm.Keyword()


@odm.model(index=False, store=False)
class DockerConfigDelta(odm.Model):
    allow_internet_access = odm.Optional(odm.Boolean())
    command = odm.Optional(odm.List(odm.Keyword()))
    cpu_cores = odm.Optional(odm.Float())
    environment = odm.Optional(odm.List(odm.Compound(EnvironmentVariableDelta)))
    image = odm.Optional(odm.Keyword())
    ram_mb = odm.Optional(odm.Integer())


@odm.model(index=False, store=False)
class UpdateSourceDelta(odm.Model):
    headers = odm.Optional(odm.List(odm.Compound(EnvironmentVariableDelta)))
    name = odm.Optional(odm.Keyword())
    password = odm.Optional(odm.Keyword())
    pattern = odm.Optional(odm.Keyword())
    public_key = odm.Optional(odm.Keyword())
    uri = odm.Optional(odm.Keyword())
    username = odm.Optional(odm.Keyword())


@odm.model(index=False, store=False)
class UpdateConfigDelta(odm.Model):
    # build_options = odm.Optional(odm.Compound(DockerfileConfigDelta))
    generates_signatures = odm.Optional(odm.Boolean(), index=True)
    method = odm.Optional(odm.Enum(values=['run', 'build']))
    run_options = odm.Optional(odm.Compound(DockerConfigDelta))
    sources = odm.Optional(odm.List(odm.Compound(UpdateSourceDelta)))
    update_interval_seconds = odm.Optional(odm.Integer())


@odm.model(index=False, store=False)
class SubmissionParamsDelta(odm.Model):
    default = odm.Optional(odm.Any())
    name = odm.Optional(odm.Keyword())
    type = odm.Optional(odm.Enum(values=['str', 'int', 'list', 'bool']))
    value = odm.Optional(odm.Any())


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
    dependencies = odm.Optional(odm.List(odm.Compound(DockerConfigDelta)))

    update_config: UpdateConfigDelta = odm.Optional(odm.Compound(UpdateConfigDelta))
