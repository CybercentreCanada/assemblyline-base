FROM sgaroncse/v3_service_base_dev:3.3.2

ENV SERVICE_PATH alsvc_pdfid.PDFId

# Clone PDFId service code
WORKDIR /opt/al/al_services
RUN git config --global http.proxy http://proxy.dmz.ava.local:3128
RUN git config --global https.proxy https://proxy.dmz.ava.local:3128
RUN git clone https://bitbucket.org/cse-assemblyline/alsvc_pdfid.git