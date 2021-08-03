ARG build_no=dev0
FROM localhost:32000/cccs/assemblyline:$build_no

CMD ["gunicorn", "assemblyline_service_server.patched:app", "--config=python:assemblyline_service_server.gunicorn_config", "--worker-class", "gevent"]
