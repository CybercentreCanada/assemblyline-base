# NOTE: to build this container you must be in a directory where assemblyline-base, assemblyline-ui,
# assemblyline-core, assemblyline-service-server and assemblyline-service-client code is checked out
FROM python:3.11-slim-bookworm

# Upgrade packages
RUN apt-get update && apt-get -yy upgrade && rm -rf /var/lib/apt/lists/*

# SSDEEP pkg requirments
RUN apt-get update -yy \
    && apt-get install -yy build-essential libffi-dev libfuzzy-dev libldap2-dev libsasl2-dev libmagic1 libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/lib/assemblyline
RUN mkdir -p /var/lib/assemblyline/flowjs
RUN mkdir -p /var/lib/assemblyline/bundling
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
WORKDIR /opt/alv4

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-service-server:/opt/alv4/assemblyline-service-client:/opt/alv4/assemblyline_client:/opt/alv4/assemblyline-ui

RUN pip install --upgrade pip
RUN pip install debugpy

COPY assemblyline-base assemblyline-base
RUN pip install --no-warn-script-location -e ./assemblyline-base[test]

COPY assemblyline-core assemblyline-core
RUN pip install --no-warn-script-location -e ./assemblyline-core[test]

COPY assemblyline-ui assemblyline-ui
RUN pip install --no-warn-script-location -e ./assemblyline-ui[test,socketio]

COPY assemblyline_client assemblyline_client
RUN pip install --no-warn-script-location -e ./assemblyline_client[test]

RUN pip uninstall -y assemblyline
RUN pip uninstall -y assemblyline_core
RUN pip uninstall -y assemblyline_ui
RUN pip uninstall -y assemblyline_client
