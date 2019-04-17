FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_frankenstrings.FrankenStrings

RUN apt-get update && apt-get install -y \
  libyaml-dev \
  python-levenshtein

RUN pip install \
  awscli \
  ipython

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/fuzzywuzzy-master.zip /tmp
RUN aws s3 cp s3://assemblyline-support/vivisect-master.zip /tmp
RUN aws s3 cp s3://assemblyline-support/viv-utils-master.zip /tmp
RUN aws s3 cp s3://assemblyline-support/flare-floss-master.zip /tmp

# Pip install the support files
RUN pip install \
  /tmp/fuzzywuzzy-master.zip \
  /tmp/vivisect-master.zip \
  /tmp/viv-utils-master.zip \
  /tmp/flare-floss-master.zip

# Cleanup
RUN rm -rf /tmp

# Clone FrankenStrings service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_frankenstrings.git