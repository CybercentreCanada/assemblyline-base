from assemblyline import odm


@odm.model(description="These are messages sent by dispatcher on the watch queue")
class WatchQueueMessage(odm.Model):
    cache_key = odm.Optional(odm.Keyword(), description="Cache key")
    status = odm.Enum(values=['FAIL', 'OK', 'START', 'STOP'], description="Watch statuses")


CREATE_WATCH = 'CREATE_WATCH'
LIST_OUTSTANDING = 'LIST_OUTSTANDING'
UPDATE_BAD_SID = 'UPDATE_BAD_SID'


@odm.model(description="Create Watch Message")
class CreateWatch(odm.Model):
    queue_name: str = odm.Keyword(description="Name of queue")
    submission: str = odm.Keyword(description="Submission ID")


@odm.model(description="List Outstanding Message")
class ListOutstanding(odm.Model):
    response_queue: str = odm.Keyword(description="Response queue")
    submission: str = odm.Keyword(description="Submission ID")


MESSAGE_CLASSES = {
    CREATE_WATCH: CreateWatch,
    LIST_OUTSTANDING: ListOutstanding,
    UPDATE_BAD_SID: str
}


@odm.model(description="Model of Dispatcher Command Message")
class DispatcherCommandMessage(odm.Model):
    kind: str = odm.Enum(values=list(MESSAGE_CLASSES.keys()), description="Kind of message")
    payload_data = odm.Any(description="Message payload")

    def payload(self):
        return MESSAGE_CLASSES[self.kind](self.payload_data)
