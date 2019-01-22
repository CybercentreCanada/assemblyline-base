
from flask import abort, current_app, Blueprint, jsonify, make_response, request, session as flsk_session, Response
from sys import exc_info
from traceback import format_tb

from assemblyline.common.str_utils import safe_str
from assemblyline.service.config import BUILD_LOWER, BUILD_MASTER, BUILD_NO, RATE_LIMITER

API_PREFIX = "/api"
api = Blueprint("api", __name__, url_prefix=API_PREFIX)


def make_subapi_blueprint(name, api_version=3):
    """ Create a flask Blueprint for a subapi in a standard way. """
    return Blueprint(f"apiv{api_version}.{name}", name, url_prefix='/'.join([API_PREFIX, f"v{api_version}", name]))


####################################
# API Helper func and decorators
def make_api_response(data, err="", status_code=200, cookies=None):
    if type(err) is Exception:
        trace = exc_info()[2]
        err = ''.join(['\n'] + format_tb(trace) +
                      ['%s: %s\n' % (err.__class__.__name__, str(err))]).rstrip('\n')

    resp = make_response(jsonify({"api_response": data,
                                  "api_error_message": err,
                                  "api_server_version": "%s.%s.%s" % (BUILD_MASTER, BUILD_LOWER, BUILD_NO),
                                  "api_status_code": status_code}),
                         status_code)

    if isinstance(cookies, dict):
        for k, v in cookies.items():
            resp.set_cookie(k, v)

    return resp


def make_file_response(data, name, size, status_code=200, content_type="application/octet-stream"):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    response = make_response(data, status_code)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Length"] = size
    response.headers["Content-Disposition"] = 'attachment; filename="%s"' % safe_str(name)
    return response


def stream_file_response(reader, name, size, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    chunk_size = 65535

    def generate():
        reader.seek(0)
        while True:
            data = reader.read(chunk_size)
            if not data:
                break
            yield data

    headers = {"Content-Type": 'application/octet-stream',
               "Content-Length": size,
               "Content-Disposition": 'attachment; filename="%s"' % safe_str(name)}
    return Response(generate(), status=status_code, headers=headers)


def make_binary_response(data, size, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    response = make_response(data, status_code)
    response.headers["Content-Type"] = 'application/octet-stream'
    response.headers["Content-Length"] = size
    return response


def stream_binary_response(reader, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    chunk_size = 4096

    def generate():
        reader.seek(0)
        while True:
            data = reader.read(chunk_size)
            if not data:
                break
            yield data

    return Response(generate(), status=status_code, mimetype='application/octet-stream')


#####################################
# API list API (API inception)
# noinspection PyUnusedLocal
@api.route("/")
def api_version_list(**kwargs):
    """
    List all available API versions.
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    ["v1", "v2", "v3"]         #List of API versions available
    """
    api_list = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith("/api/"):
            version = rule.rule[5:].split("/", 1)[0]
            if version not in api_list and version != '':
                # noinspection PyBroadException
                try:
                    int(version[1:])
                except Exception:
                    continue
                api_list.append(version)

    return make_api_response(api_list)
