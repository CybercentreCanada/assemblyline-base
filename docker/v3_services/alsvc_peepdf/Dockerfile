FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_peepdf.PeePDF

RUN apt-get update && apt-get install -y \
  python-pyrex \
  swig \
  libemu-dev \
  libnspr4-dev \
  pkg-config

RUN pip install \
  nose \
  python-spidermonkey

# Clone PeePDF service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_peepdf.git