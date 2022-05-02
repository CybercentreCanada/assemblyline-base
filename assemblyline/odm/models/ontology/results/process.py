from assemblyline import odm


@odm.model(description="Details about the characteristics used to identify an object")
class ObjectID(odm.Model):
    guid = odm.Text(description="The GUID associated with the object")
    tag = odm.Optional(odm.Text(), description="The normalized tag of the object")
    treeid = odm.Optional(odm.Text(), description="The hash of the tree ID")
    processtree = odm.Optional(odm.Keyword(), description="Human-readable tree ID (concatenation of tags)")
    time_observed = odm.Optional(odm.Date(), description="The time at which the object was observed")


@odm.model(description="Details about a process")
class Process(odm.Model):
    oid = odm.UUID(description="Unique identifier of ontology")
    oid_parent = odm.Optional(odm.UUID(), description="Parent of this ontology")
    oid_children = odm.Optional(odm.List(odm.UUID()), description="Children of this ontology")

    objectid = odm.Compound(ObjectID, description="The object ID of the process object")

    # Parent process details
    pobjectid = odm.Compound(ObjectID, description="The object ID of the parent process object")
    pimage = odm.Optional(odm.Text(), description="The image of the parent process that spawned this process")
    pcommand_line = odm.Optional(odm.Text(), description="The command line that the parent process ran")
    ppid = odm.Optional(odm.Integer(), description="The process ID of the parent process")

    pid = odm.Optional(odm.Integer(), description="The process ID")
    image = odm.Text(default="<unknown_image>", description="The image of the process")
    command_line = odm.Optional(odm.Text(), description="The command line that the process ran")
    start_time = odm.Date(description="The time of creation for the process")
    end_time = odm.Date(description="The time of termination for the process")
    integrity_level = odm.Optional(odm.Text(), description="The integrity level of the process")
    image_hash = odm.Optional(odm.Text(), description="The hash of the file run")
    original_file_name = odm.Optional(odm.Text(), description="The original name of the file")
