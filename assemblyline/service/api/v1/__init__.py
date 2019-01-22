from flask import current_app, Blueprint, request

from assemblyline.service.api.base import make_api_response

API_PREFIX = "/api/v1"
apiv1 = Blueprint("apiv1", __name__, url_prefix=API_PREFIX)
apiv1._doc = "Version 1 Api Documentation"


#####################################
# API DOCUMENTATION
# noinspection PyProtectedMember,PyBroadException
@apiv1.route("/")
def get_api_documentation(**_):
    """
    Full API doc.

    Loop through all registered API paths and display their documentation.
    Returns a list of API definition.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [                            # LIST of:
     {'name': "Api Doc",                # Name of the api
      'path': "/api/path/<variable>/",  # API path
      'ui_only': false,                 # Is UI only API
      'methods': ["GET", "POST"],       # Allowed HTTP methods
      'description': "API doc.",        # API documentation
      'id': "api_doc",                  # Unique ID for the API
      'function': "apiv3.api_doc",      # Function called in the code
      'complete' : True},               # Is the API stable?
      ...]
    """
    api_blueprints = {}
    api_list = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith(request.path):
            methods = []

            for item in rule.methods:
                if item != "OPTIONS" and item != "HEAD":
                    methods.append(item)

            func = current_app.view_functions[rule.endpoint]

            doc_string = func.__doc__
            func_title = " ".join([x.capitalize() for x in rule.endpoint[rule.endpoint.rindex(".") + 1:].split("_")])
            blueprint = rule.endpoint[rule.endpoint.index(".") + 1:rule.endpoint.rindex(".")]
            if not blueprint:
                blueprint = "documentation"

            if blueprint not in api_blueprints:
                try:
                    doc = current_app.blueprints[rule.endpoint[:rule.endpoint.rindex(".")]]._doc
                except Exception:
                    doc = ""

                api_blueprints[blueprint] = doc

            try:
                description = "\n".join([x[4:] for x in doc_string.splitlines()])
            except Exception:
                description = "[INCOMPLETE]\n\nTHIS API HAS NOT BEEN DOCUMENTED YET!"

            if rule.endpoint == "apiv1.api_doc":
                api_id = "documentation_api_doc"
            else:
                api_id = rule.endpoint.replace("apiv1.", "").replace(".", "_")

            api_list.append({
                "name": func_title,
                "id": api_id,
                "function": rule.endpoint,
                "path": rule.rule, "ui_only": rule.rule.startswith("%sui/" % request.path),
                "methods": methods, "description": description,
                "complete": "[INCOMPLETE]" not in description
            })
    return make_api_response({"apis": api_list, "blueprints": api_blueprints})
