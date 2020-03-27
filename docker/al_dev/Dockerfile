FROM python:3.7-slim-stretch
# NOTE: to build this container you must be in a directory where alv4, alv4_ui, alv4_core, alv4_service_server and
# alv4_service_client code is checked out

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/alv4:/opt/alv4/alv4_core:/opt/alv4/alv4_service_server:/opt/alv4/alv4_service_client:/opt/alv4/alv4_ui

# SSDEEP pkg requirments
RUN apt-get update && apt-get install -yy build-essential libffi-dev libfuzzy-dev libldap2-dev libsasl2-dev libmagic1 && rm -rf /var/lib/apt/lists/*

# Pipy packages requirements
RUN pip install --no-cache-dir assemblyline[test] assemblyline-core assemblyline-ui assemblyline-service-server
RUN pip uninstall -y assemblyline assemblyline-core assemblyline-ui assemblyline-service-server

# clear pip cache
RUN rm -rf ~/.cache/pip

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/lib/assemblyline
RUN mkdir -p /var/lib/assemblyline/flowjs
RUN mkdir -p /var/lib/assemblyline/bundling
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
WORKDIR /opt/alv4

CMD pip list