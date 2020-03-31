FROM python:3.7-slim

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
RUN cp assemblyline-base/test/bitbucket/config.yml /etc/assemblyline/
RUN pip install -e ./assemblyline-base[test]
RUN pip uninstall -y assemblyline

COPY assemblyline-core assemblyline-core
RUN pip install -e ./assemblyline-core[test]
RUN pip uninstall -y assemblyline_core
