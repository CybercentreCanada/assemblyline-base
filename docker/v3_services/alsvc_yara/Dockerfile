FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_yara.Yara

RUN pip install \
  awscli

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

# Clone Yara service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_yara.git