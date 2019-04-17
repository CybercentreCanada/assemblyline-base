FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_tagcheck.TagCheck

# Clone TagCheck service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_tagcheck.git

RUN python /opt/al/al_services/alsvc_tagcheck/tsig.py /opt/al/al_services/alsvc_tagcheck/sample_sigset.csv