FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_cfmd.CFMD

RUN apt-get update && apt-get install -y \
  libmysqlclient-dev

RUN pip install \
  MySQL-python==1.2.5

# Clone CFMD service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_cfmd.git