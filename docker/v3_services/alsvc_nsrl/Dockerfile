FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_nsrl.NSRL

RUN apt-get update && apt-get install -y \
  libpq-dev

RUN pip install \
  psycopg2

# Clone NSRL service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_nsrl.git