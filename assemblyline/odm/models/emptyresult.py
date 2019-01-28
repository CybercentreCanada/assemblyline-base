from assemblyline import odm


@odm.model(index=False, store=False)
class Milestone(odm.Model):
    service_started = odm.Date(default_set=True)    # Date the service started scanning
    service_completed = odm.Date(default_set=True)  # Date the service finished scanning


@odm.model(index=True, store=True)
class ResponseBody(odm.Model):
    milestones = odm.Compound(Milestone)                        # Milestone block
    service_version = odm.Keyword(store=False)                  # Version of the service that ran on the file
    service_name = odm.Keyword(copyto="__text__")               # Name of the service that scan the file
    service_context = odm.Keyword(index=False, store=False)     # Context about the service that was running
    service_debug_info = odm.Keyword(index=False, store=False)  # Debug information where the service was processed


@odm.model(index=True, store=True)
class EmptyResult(odm.Model):
    classification = odm.Classification()   # Aggregate classification for the result
    created = odm.Date(default="NOW")       # Date at which the result object got created
    expiry_ts = odm.Date(store=False)       # Expiry time stamp
    response = odm.Compound(ResponseBody)   # The body of the response from the service
    sha256 = odm.Keyword(store=False)       # SHA256 of the file the result object relates to

    def build_key(self, conf_key=None):
        key_list = [
            self.sha256,
            self.response.service_name.replace('.', '_'),
            f"v{self.response.service_version.replace('.', '_')}"
        ]

        if conf_key:
            key_list.append('c' + conf_key.replace('.', '_'))
        else:
            key_list.append("c0")

        key_list.append("e")

        return '.'.join(key_list)
