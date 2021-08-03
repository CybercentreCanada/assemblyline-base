ARG build_no=dev0
FROM localhost:32000/cccs/assemblyline:$build_no

CMD ["gunicorn", "assemblyline_ui.patched:app", "--config=python:assemblyline_ui.gunicorn_config", "--worker-class", "gevent"]
