from assemblyline import odm
from assemblyline.odm.models.ontology.types.objectid import ObjectID


# Details about a process
class Process(odm.Model):
    # The object ID of the process object
    objectid = odm.Compound(ObjectID)

    # Parent process details
    # The GUID associated with the parent process
    pobjectid = odm.Compound(ObjectID)
    # The image of the parent process that spawned this process
    pimage = odm.Optional(odm.Text())
    # The command line that the parent process ran
    pcommand_line = odm.Optional(odm.Text())
    # The process ID of the parent process
    ppid = odm.Optional(odm.Integer())

    # The process ID
    pid = odm.Optional(odm.Integer())
    # The image of the process
    image = odm.Text(default="<unknown_image>")
    # The command line that the process ran
    command_line = odm.Optional(odm.Text())
    # The time of creation for the process
    start_time = odm.Date()
    # The time of termination for the process
    end_time = odm.Date()
    # Human readable tree ID (concatenation of process names)
    rich_id = odm.Optional(odm.Text())
    # The integrity level of the process
    integrity_level = odm.Optional(odm.Text())
    # The hash of the file run
    image_hash = odm.Optional(odm.Text())
    # The original name of the file
    original_file_name = odm.Optional(odm.Text())
