from assemblyline import odm

OS_TYPES = ["windows", "linux"]
OS_VARIANTS_WINDOWS = ["winxp", "win7", "win10"]
OS_VARIANTS_LINUX = ["ubuntuprecise", "ubuntutrusty", "ubuntuxenial", "ubuntubionic"]
OS_VARIANTS = OS_VARIANTS_WINDOWS + OS_VARIANTS_LINUX


@odm.model(index=True, store=True)
class VM(odm.Model):
    enabled = odm.Boolean(default=True)
    name = odm.Keyword(copyto="__text__")
    num_workers = odm.Integer(default=1)
    os_type = odm.Enum(values=OS_TYPES)
    os_variant = odm.Enum(values=OS_VARIANTS)
    ram = odm.Integer(default=1024)
    revert_every = odm.Integer(default=600)
    vcpus = odm.Integer(default=1)
    virtual_disk_url = odm.Keyword()
