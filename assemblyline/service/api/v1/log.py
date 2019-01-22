from flask import request
import logging

from assemblyline.service.api.base import make_api_response, make_subapi_blueprint

SUB_API = 'log'
log_api = make_subapi_blueprint(SUB_API, api_version=1)
log_api._doc = "Log messages"


@log_api.route("/info/", methods=["POST"])
def info(**_):
    """
    Log an INFO message

    Variables:
    None

    Arguments:
    None

    Data Block:
    {'log': 'assemblyline.svc.extract',
     'msg': 'info message'}

    Result example:
    {"success": true }    # Info message logged successfully
    """
    data = request.json

    log = logging.getLogger(data['log'])
    log.info(data['msg'])

    return make_api_response({"success": True})