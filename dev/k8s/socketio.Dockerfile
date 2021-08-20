ARG build_no=latest
FROM localhost:32000/cccs/assemblyline:$build_no

CMD ["python", "-m", "debugpy", "--listen", "localhost:5678", "-m", "gunicorn", "-b", ":5002", "-w", "1", "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "assemblyline_ui.socketsrv:app"]
