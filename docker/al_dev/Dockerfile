FROM python:3.6-stretch
# NOTE: to build this container you must be in a directory where alv4, alv4_ui, alv4_core, alv4_service_server and
# alv4_service_client code is checked out

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/alv4:/opt/alv4/alv4_core:/opt/alv4/alv4_service_server:/opt/alv4/alv4_service_client:/opt/alv4/alv4_ui

# SSDEEP pkg requirments
RUN apt-get update
RUN apt-get install -yy build-essential libffi-dev libfuzzy-dev

# Pipy packages requirements
RUN pip3 install assemblyline assemblyline-ui assemblyline-service-server

# Install all the dependencies for core (+core)
COPY alv4_core /tmp/alv4_core
RUN pip3 install -e /tmp/alv4_core
RUN rm -rf /tmp/alv4_core

# Clear out the packages we installed only for their dependencies
RUN pip3 uninstall -y assemblyline assemblyline-core assemblyline-ui assemblyline-service-server

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
WORKDIR /opt/alv4

CMD pip list