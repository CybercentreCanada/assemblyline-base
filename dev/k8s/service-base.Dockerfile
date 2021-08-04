ARG build_no=latest
FROM localhost:32000/cccs/assemblyline:$build_no

# Setup environment varibles
ENV PYTHONPATH $PYTHONPATH:/opt/al_service
ENV SERVICE_API_HOST http://al_service_server:5003
ENV SERVICE_API_AUTH_KEY ThisIsARandomAuthKey...ChangeMe!
ENV CONTAINER_MODE true

RUN mkdir -p /opt/al_service
RUN touch /opt/al_service/__init__.py

CMD ["python", "/opt/alv4/assemblyline-v4-service/docker/process_handler.py"]
