FROM python:3.9-slim-buster

ENV PYTHONPATH /opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-service-server:/opt/alv4/assemblyline-service-client:/opt/alv4/assemblyline-ui:/opt/alv4/assemblyline-v4-service:/opt/alv4/assemblyline-service-client

# SSDEEP pkg requirments
RUN apt-get update -yy \
    && apt-get install -yy build-essential libffi-dev libfuzzy-dev libldap2-dev libsasl2-dev libmagic1 \
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

#
COPY assemblyline-base assemblyline-base
RUN pip install -e ./assemblyline-base[test]

COPY assemblyline-core assemblyline-core
RUN pip install -e ./assemblyline-core[test]

COPY assemblyline-ui assemblyline-ui
RUN pip install -e ./assemblyline-ui[socketio,test]

COPY assemblyline_client assemblyline_client
RUN pip install -e ./assemblyline_client[test]

COPY assemblyline-service-server assemblyline-service-server
RUN pip install -e ./assemblyline-service-server[test]

COPY assemblyline-service-client assemblyline-service-client
RUN pip install -e ./assemblyline-service-client[test]

COPY assemblyline-v4-service assemblyline-v4-service
RUN pip install -e ./assemblyline-v4-service[test]


RUN pip uninstall -y assemblyline
RUN pip uninstall -y assemblyline_core
RUN pip uninstall -y assemblyline_ui
RUN pip uninstall -y assemblyline_service_server
RUN pip uninstall -y assemblyline_client
RUN pip uninstall -y assemblyline_service_client
RUN pip uninstall -y assemblyline_v4_service
