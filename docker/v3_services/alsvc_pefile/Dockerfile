FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_pefile.PEFile

RUN pip install \
  pefile==2017.11.5 \
  ssdeep \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/signify-master.zip /tmp
RUN aws s3 cp s3://assemblyline-support/apiscout-master.zip /tmp

RUN pip install \
  /tmp/signify-master.zip \
  /tmp/apiscout-master.zip

# Cleanup
RUN rm -rf /tmp

# Clone PEFile service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_pefile.git