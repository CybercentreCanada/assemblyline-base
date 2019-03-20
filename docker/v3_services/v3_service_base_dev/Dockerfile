FROM ubuntu:18.04

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/alv4:/opt/alv4/alv4_core:/opt/alv4/alv4_service_api:/opt/alv4/alv4_service_client:/opt/al/al_services:/opt/alv4/alv4_ui
ENV SERVICE_API_HOST http://service_server:5003

RUN apt-get update && apt-get install -y \
  git \
  libfuzzy-dev \
  python \
  python-pip

# Pipy packages requirements
COPY alv4/assemblyline/requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

COPY alv4_service_client/requirements.txt /tmp
RUN sed -i.old -e "s/assemblyline-core//g" -e "s/assemblyline//g" /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Cleanup
RUN rm /tmp/requirements.txt*

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
RUN mkdir -p /opt/al/al_services
RUN touch /opt/al/al_services/__init__.py
WORKDIR /opt/al