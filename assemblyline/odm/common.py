from assemblyline import odm


@odm.model()
class Resources(odm.Model):
    cpu_usage = odm.Float()
    disk_usage_free = odm.Integer()
    disk_usage_percent = odm.Float()
    mem_usage = odm.Float()


@odm.model()
class HostInfo(odm.Model):
    host = odm.Keyword()
    ip = odm.Keyword()
    mac_address = odm.Keyword()
