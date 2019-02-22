from assemblyline import odm
from assemblyline.odm.common import HostInfo, Resources

MSG_TYPES = {"ServiceHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.old.service.ServiceMessage"


@odm.model()
class ServiceProfile(odm.Model):
    service_overrides = odm.Mapping(odm.Keyword())
    workers = odm.Integer()


@odm.model()
class ProfileDefinition(odm.Model):
    services = odm.Mapping(odm.Compound(ServiceProfile))


@odm.model()
class WorkerInfo(odm.Model):
    revision = odm.Keyword()


@odm.model()
class Service(odm.Model):
    name = odm.Keyword()
    num_workers = odm.Integer()
    workers = odm.Mapping(odm.Compound(WorkerInfo))


@odm.model()
class Services(odm.Model):
    details = odm.Mapping(odm.Compound(Service))


@odm.model()
class VmDetail(odm.Model):
    mac_address = odm.Keyword()


@odm.model()
class Heartbeat(odm.Model):
    hostinfo = odm.Compound(HostInfo)
    profile_definition = odm.Compound(ProfileDefinition)
    resources = odm.Compound(Resources)
    service = odm.Compound(Services)
    time = odm.Date()
    vmm = odm.Mapping(odm.Compound(VmDetail))


@odm.model()
class ServiceMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ServiceHeartbeat")
    sender = odm.Keyword()
