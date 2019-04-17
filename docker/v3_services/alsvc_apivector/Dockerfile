FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_apivector.ApiVector

RUN pip install \
  awscli \
  requests

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/apiscout-master.zip /tmp

RUN pip install \
  /tmp/apiscout-master.zip

# Cleanup
RUN rm -rf /tmp

# Clone ApiVector service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_apivector.git
