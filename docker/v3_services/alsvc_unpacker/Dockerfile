FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_unpacker.Unpacker

RUN apt-get update && apt-get install -y \
  upx-ucl

# Clone Unpacker service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_unpacker.git