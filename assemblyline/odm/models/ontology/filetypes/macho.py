from assemblyline import odm


@odm.model(index=True, store=False)
class MachO(odm.Model):
    @odm.model(index=True, store=False)
    class Header(odm.Model):
        entrypoint = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        cpu_type = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        cpu_sub_type = odm.Optional(odm.Integer())
        file_type = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        flags = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        numberof_loadcommands = odm.Optional(odm.Integer())
        sizeof_loadcommands = odm.Optional(odm.Integer())
        minimum_os_version = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        platform = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        sdk_version = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        linker = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        base = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        is_ios = odm.Optional(odm.Boolean())
        is_macos = odm.Optional(odm.Boolean())
        is_position_independent = odm.Optional(odm.Boolean())
        is_norized = odm.Optional(odm.Boolean())
        uuid = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))

    @odm.model(index=True, store=False)
    class Segments(odm.Model):
        offset = odm.Optional(odm.Integer())
        size = odm.Optional(odm.Integer())
        flags = odm.Optional(odm.Integer())
        index = odm.Optional(odm.Integer())
        numberof_sections = odm.Optional(odm.Integer())
        name = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        virtual_address = odm.Optional(odm.Integer())
        virtual_size = odm.Optional(odm.Integer())
        initial_protection = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        max_protection = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))

    @odm.model(index=True, store=False)
    class Sections(odm.Model):
        type = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        name = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        flags = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        alignment = odm.Optional(odm.Integer())
        relocation_offset = odm.Optional(odm.Integer())
        numberof_relocations = odm.Optional(odm.Integer())
        entropy = odm.Optional(odm.Float())
        segment_name = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        reserved1 = odm.Optional(odm.Integer())
        reserved2 = odm.Optional(odm.Integer())
        reserved3 = odm.Optional(odm.Integer())
        hash = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))

    @odm.model(index=True, store=False)
    class Libraries(odm.Model):
        name = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        timestamp = odm.Optional(odm.Integer())
        compatibility_version = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        current_version = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))

    @odm.model(index=True, store=False)
    class LoadCommands(odm.Model):
        name = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        offset = odm.Optional(odm.Integer())
        size = odm.Optional(odm.Integer())

    @odm.model(index=True, store=False)
    class Notarization(odm.Model):
        flags = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        hash_offset = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        hash_size = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        platform = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        codedir_size = odm.Optional(odm.Integer())
        identifier_string = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        version = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        entitlement = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
        requirement = odm.Optional(odm.EmptyableKeyword(copyto="__text__"))
