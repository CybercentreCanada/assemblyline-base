from assemblyline import odm


# These are messages sent by dispatcher on the watch queue
@odm.model()
class WatchQueueMessage(odm.Model):
    cache_key = odm.Optional(odm.Keyword())
    status = odm.Enum(values=['FAIL', 'OK', 'START', 'STOP'])