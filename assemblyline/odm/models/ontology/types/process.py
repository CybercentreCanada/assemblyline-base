from assemblyline import odm
from assemblyline.odm.models.ontology.types.objectid import ObjectID


@odm.model(description="Details about a process")
class Process(odm.Model):
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
