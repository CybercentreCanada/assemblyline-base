from assemblyline import odm


@odm.model(index=False, store=False)
class EnvironmentVariableDelta(odm.Model):
    name = odm.Keyword()
    value = odm.Keyword()


@odm.model(index=False, store=False)
class DockerConfigDelta(odm.Model):
    image = odm.Optional(odm.Keyword())
    command = odm.Optional(odm.List(odm.Keyword()))
    environment = odm.Optional(odm.List(odm.Compound(EnvironmentVariableDelta)))
    network = odm.Optional(odm.List(odm.Keyword()))


@odm.model(index=False, store=False)
class UpdateSourceDelta(odm.Model):
    uri = odm.Optional(odm.Keyword())
    name = odm.Optional(odm.Keyword())
    username = odm.Optional(odm.Keyword())
    password = odm.Optional(odm.Keyword())
    headers = odm.Optional(odm.Mapping(odm.Keyword()))
    public_key = odm.Optional(odm.Keyword())
    pattern = odm.Optional(odm.Keyword())


@odm.model(index=False, store=False)
class UpdateConfigDelta(odm.Model):
    method = odm.Optional(odm.Enum(values=['run', 'build']))
    sources = odm.Optional(odm.List(odm.Compound(UpdateSourceDelta)))
    update_interval_seconds = odm.Optional(odm.Integer())
    run_options = odm.Optional(odm.Compound(DockerConfigDelta))
    # build_options = odm.Optional(odm.Compound(DockerfileConfigDelta))
    generates_signatures = odm.Optional(odm.Boolean())


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
    default_result_classification = odm.Optional(odm.ClassificationString())
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
    dependencies = odm.Optional(odm.List(odm.Compound(DockerConfigDelta)))

    update_config: UpdateConfigDelta = odm.Optional(odm.Compound(UpdateConfigDelta))
