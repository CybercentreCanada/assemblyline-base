FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_iparse.IPArse

RUN apt-get update && apt-get install -y \
  p7zip-full

RUN pip install \
  biplist

# Clone IPArse service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_iparse.git