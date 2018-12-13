from assemblyline import odm

ROLES = {"controller", "hostagent", "middleman", "dispatcher", "orchestrator"}


@odm.model(index=False, store=False)
class ServiceAffinity(odm.Model):
    allowed_services = odm.Keyword(default=".*")
    banned_services = odm.Keyword(default="")


@odm.model(index=False, store=False)
class Platform(odm.Model):
    node = odm.Keyword()
    system = odm.Enum(values={"Linux", "Windows"})
    machine = odm.Keyword()
    version = odm.Text()
    release = odm.Keyword()
    proc = odm.Keyword()


@odm.model(index=True, store=True)
class MachineInfo(odm.Model):
    uid = odm.Keyword(index=False, store=False)
    memory = odm.Float()
    cores = odm.Integer()
    os = odm.Text()
    name = odm.Keyword(index=False, store=False)


@odm.model(index=True, store=True)
class Node(odm.Model):
    is_vm = odm.Boolean(default=False, index=False, store=False)
    roles = odm.List(odm.Enum(values=ROLES), index=False, store=False)
    ip = odm.Keyword()
    hostname = odm.Keyword()
    enabled = odm.Boolean(default=True)
    vm_host = odm.Keyword(index=False, store=False)
    mac_address = odm.Keyword()
    machine_info = odm.Compound(MachineInfo)
    platform = odm.Compound(Platform)
    service_affinity = odm.Compound(ServiceAffinity)
