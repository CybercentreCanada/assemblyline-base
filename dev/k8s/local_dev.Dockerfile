FROM python:3.9-slim-buster

ENV PYTHONPATH=${PYTHONPATH}:/var/lib/assemblyline/.local/lib/python3.9/site-packages/:/opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-service-server:/opt/alv4/assemblyline-service-client:/opt/alv4/assemblyline-ui:/opt/alv4/assemblyline_client:/opt/alv4/assemblyline-v4-service:/opt/alv4/assemblyline-service-client

# SSDEEP pkg requirments
RUN apt-get update -yy \
    && apt-get install -yy build-essential libffi-dev libfuzzy-dev libldap2-dev libsasl2-dev libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Create Assemblyline source directory
RUN useradd -b /var/lib -U -m assemblyline
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/lib/assemblyline
RUN mkdir -p /var/lib/assemblyline/flowjs
RUN mkdir -p /var/lib/assemblyline/bundling
RUN mkdir -p /var/log/assemblyline
WORKDIR /opt/alv4
ENV PATH=/var/lib/assemblyline/.local/bin:$PATH

# Install and uninstall the pypi version, so that docker can cache the
# dependency installation making repeated rebuilds with changing local changes faster
RUN pip install assemblyline[test] assemblyline_core[test] assemblyline_ui[test,scoketio] \
                assemblyline_client[test] assemblyline_service_server[test] \
                assemblyline_service_client[test] assemblyline_v4_service[test] \
    && pip uninstall -y assemblyline assemblyline_core assemblyline_ui \
                    assemblyline_service_server assemblyline_client \
                    assemblyline_service_client assemblyline_v4_service

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


# RUN pip uninstall -y assemblyline assemblyline_core assemblyline_ui \
#                     assemblyline_service_server assemblyline_client \
#                     assemblyline_service_client assemblyline_v4_service