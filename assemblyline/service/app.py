import logging

from flask import Flask

from assemblyline.service.api.base import api
from assemblyline.service.api.v1 import apiv1
from assemblyline.service.api.v1.log import log_api

app = Flask("alsvc")
app.config["DEBUG"] = True

app.register_blueprint(api)
app.register_blueprint(apiv1)
app.register_blueprint(log_api)


def main():
    app.logger.setLevel(logging.INFO)
    # if config.PROFILE:
    #     from werkzeug.contrib.profiler import ProfilerMiddleware
    #     app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
    print(app.url_map)
    app.jinja_env.cache = {}
    app.run(host="0.0.0.0", debug=True)


if __name__ == '__main__':
    main()
