FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_configdecoder.ConfigDecoder

RUN pip install \
  awscli \
  pefile==2017.11.5

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/yara-python-3.8.1.tar.gz /tmp

RUN mkdir -p /opt/al/support/yara
RUN tar -zxf /tmp/yara-python-3.8.1.tar.gz -C /opt/al/support/yara
RUN python /opt/al/support/yara/yara-python-3.8.1/setup.py build --enable-dotnet
RUN python /opt/al/support/yara/yara-python-3.8.1/setup.py install

# Cleanup
RUN rm -rf /tmp

# Clone ConfigDecoder service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_configdecoder.git

RUN python alv4/assemblyline/common/yara/yara_importer.py -f -s /opt/al/al_services/alsvc_configdecoder/rules/config_decoder_sigs.yar