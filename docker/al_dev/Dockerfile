FROM python:3.9-slim-buster
# NOTE: to build this container you must be in a directory where assemblyline-base, assemblyline-ui,
# assemblyline-core, assemblyline-service-server and assemblyline-service-client code is checked out

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-service-server:/opt/alv4/assemblyline-service-client:/opt/alv4/assemblyline-ui

# SSDEEP pkg requirments
RUN apt-get update && apt-get install -yy build-essential libffi-dev libfuzzy-dev libldap2-dev libsasl2-dev libmagic1 && rm -rf /var/lib/apt/lists/*

# Python packages requirements
RUN pip install --no-cache-dir \
   assemblyline[test] \
   assemblyline-core \
   assemblyline-ui \
   assemblyline-service-server \
   && pip uninstall -y \
   assemblyline \
   assemblyline-core \
   assemblyline-ui \
   assemblyline-service-server \
   debugpy \
   && rm -rf ~/.cache/pip


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
