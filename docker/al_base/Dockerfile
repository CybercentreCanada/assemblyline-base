FROM python:3.7-stretch

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/

# SSDEEP pkg requirments
RUN apt-get update
RUN apt-get install -yy build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev

# Pipy packages requirements
RUN pip install assemblyline assemblyline-core

# Assemblyline directories
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/storage/assemblyline
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
WORKDIR /opt/alv4


CMD pip list