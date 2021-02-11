from assemblyline import odm


# These are messages sent by dispatcher on the watch queue
@odm.model()
class WatchQueueMessage(odm.Model):
    cache_key = odm.Optional(odm.Keyword())
    status = odm.Enum(values=['FAIL', 'OK', 'START', 'STOP'])


CREATE_WATCH = 'CREATE_WATCH'
LIST_OUTSTANDING = 'LIST_OUTSTANDING'


@odm.model()
class CreateWatch(odm.Model):
    queue_name: str = odm.Keyword()
    submission: str = odm.Keyword()


@odm.model()
class ListOutstanding(odm.Model):
    response_queue: str = odm.Keyword()
    submission: str = odm.Keyword()


MESSAGE_CLASSES = {
    CREATE_WATCH: CreateWatch,
    LIST_OUTSTANDING: ListOutstanding,
}


@odm.model()
class DispatcherCommandMessage(odm.Model):
    kind: str = odm.Enum(values=list(MESSAGE_CLASSES.keys()))
    payload_data = odm.Any()

    def payload(self):
        return MESSAGE_CLASSES[self.kind](self.payload_data)
