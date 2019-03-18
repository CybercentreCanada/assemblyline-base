FROM python:2.7-stretch
# NOTE: to build this container you must be in a directory where alv4, alv4_ui, alv4_core, alv4_service_api and
# alv4_service_client code is checked out

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/alv4:/opt/alv4/alv4_core:/opt/alv4/alv4_service_api:/opt/alv4/alv4_service_client:/opt/alv4/alv4_ui

# SSDEEP pkg requirments
RUN apt-get update
RUN apt-get install -yy build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev

# Pipy packages requirements
COPY  alv4/assemblyline/requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

COPY  alv4_ui/al_ui/requirements.txt /tmp
RUN sed -i.old -e "s/assemblyline-core//g" -e "s/assemblyline//g" /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

COPY  alv4_service_api/service/requirements.txt /tmp
RUN sed -i.old -e "s/assemblyline-core//g" -e "s/assemblyline//g" /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Cleanup
RUN rm /tmp/requirements.txt*

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
WORKDIR /opt/alv4


CMD pip list