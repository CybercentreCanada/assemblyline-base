FROM python:3.9-slim-buster
# NOTE: to build this container you must be in a directory where assemblyline-base, assemblyline-ui,
# assemblyline-core, assemblyline-service-server and assemblyline-service-client code is checked out

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-service-server:/opt/alv4/assemblyline-service-client:/opt/alv4/assemblyline_client:/opt/alv4/assemblyline-ui

# Upgrade packages
RUN apt-get update && apt-get -yy upgrade && rm -rf /var/lib/apt/lists/*

# SSDEEP pkg requirments
RUN apt-get update && apt-get install -yy build-essential libssl-dev libffi-dev libfuzzy-dev libldap2-dev libsasl2-dev libmagic1 zip && rm -rf /var/lib/apt/lists/*

# Python packages requirements
RUN pip install --no-warn-script-location --no-cache-dir \
   assemblyline[test] \
   assemblyline-core \
   assemblyline-ui \
   assemblyline-service-server \
   debugpy \
   && pip uninstall -y \
   assemblyline \
   assemblyline-core \
   assemblyline-ui \
   assemblyline-service-server \
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
