FROM ubuntu:18.04

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/alv4:/opt/alv4/alv4_service_client:/opt/alv4/alv3_service:/opt/al:/opt/al/al_services
ENV SERVICE_API_HOST http://localhost:5003

RUN apt-get update && apt-get install -y \
  git \
  libfuzzy-dev \
  python \
  python-pip \
  python3 \
  python3-dev \
  python3-pip \
  supervisor

# Pipy packages requirements
RUN pip3 install assemblyline
RUN pip install assemblyline

COPY alv3_service/requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

COPY alv4_service_client/requirements.txt /tmp
RUN sed -i.old -e "s/assemblyline-core//g" -e "s/assemblyline//g" /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# Cleanup
RUN rm /tmp/requirements.txt*

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
RUN mkdir -p /opt/al/al_services
RUN touch /opt/al/al_services/__init__.py

# Supervisor
RUN mkdir -p /var/log/supervisor
COPY alv4/docker/v3_services/v3_service_base_dev/supervisord.conf /etc/supervisor/conf.d/
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]