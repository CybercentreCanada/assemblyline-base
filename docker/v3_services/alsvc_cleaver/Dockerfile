FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_cleaver.Cleaver

RUN pip install \
  hachoir-core==1.3.3 \
  hachoir-parser==1.3.4 \
  hachoir-metadata==1.3.3

# Clone Cleaver service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_cleaver.git