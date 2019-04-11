FROM sgaroncse/v3_service_base_dev:3.3.5

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
RUN mkdir -p /opt/al/support/flarefloss
WORKDIR /opt/al/support/flarefloss/
RUN aws s3 cp s3://assemblyline-support/fuzzywuzzy-master.zip .
RUN aws s3 cp s3://assemblyline-support/vivisect-master.zip .
RUN aws s3 cp s3://assemblyline-support/viv-utils-master.zip .
RUN aws s3 cp s3://assemblyline-support/flare-floss-master.zip .

# Pip install the support files
RUN pip install \
  fuzzywuzzy-master.zip \
  vivisect-master.zip \
  viv-utils-master.zip \
  flare-floss-master.zip

# Clone FrankenStrings service code
WORKDIR /opt/al/al_services
RUN git clone https://bitbucket.org/cse-assemblyline/alsvc_frankenstrings.git