from assemblyline import odm


@odm.model(index=True, store=True)
class ServiceAffinity(odm.Model):
    allowed_services = odm.Keyword(default=".*")
    banned_services = odm.Keyword(default="")


@odm.model(index=True, store=True)
class Platform(odm.Model):
    node = odm.Keyword()
    system = odm.Enum(values={"Linux", "Windows"})
    machine = odm.Keyword()
    version = odm.Text()
    release = odm.Keyword()
    proc = odm.Keyword()


@odm.model(index=True, store=True)
class MachineInfo(odm.Model):
    uid = odm.Keyword()
    memory = odm.Float()
    cores = odm.Integer()
    os = odm.Text()
    name = odm.Keyword()


@odm.model(index=True, store=True)
class Node(odm.Model):
    is_vm = odm.Boolean(default=False)
    roles = odm.List(odm.Enum(values={"controller", "hostagent", "middleman", "dispatcher", "orchestrator"}))
    ip = odm.Keyword()
    hostname = odm.Keyword()
    enabled = odm.Boolean(default=True)
    vm_host = odm.Keyword()
    mac_address = odm.Keyword()
    machine_info = odm.Compound(MachineInfo)
    platform = odm.Compound(Platform)
    service_affinity = odm.Compound(ServiceAffinity)
