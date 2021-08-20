ARG build_no=latest
FROM localhost:32000/cccs/assemblyline:$build_no

CMD ["python", "-m", "debugpy", "--listen", "localhost:5678", "-m", "gunicorn", "assemblyline_service_server.patched:app", "--config=python:assemblyline_service_server.gunicorn_config", "--worker-class", "gevent"]
