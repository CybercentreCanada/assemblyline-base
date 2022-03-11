from assemblyline import odm


# Details about a process
class Process(odm.Model):

    # The GUID associated with the process
    guid = odm.Text()

    # Parent process details
    # The GUID associated with the parent process
    pguid = odm.Optional(odm.Text())
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
    # The hash of the tree ID
    tree_id = odm.Optional(odm.Text())
    #  The normalized tag of the object
    tag = odm.Optional(odm.Text())
