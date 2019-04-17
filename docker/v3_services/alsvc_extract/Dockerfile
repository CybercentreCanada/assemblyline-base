FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_extract.Extract

RUN apt-get update && apt-get install -y \
  libssl-dev \
  p7zip-full \
  p7zip-rar \
  unace-nonfree \
  poppler-utils \
  python-lxml \
  unrar

RUN pip install \
  tnefparse \
  olefile \
  beautifulsoup4 \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/msoffice.tar.gz /tmp
RUN aws s3 cp s3://assemblyline-support/cybozulib.tar.gz /tmp

# Extract the tar files and make msoffice
RUN mkdir -p /opt/al/support/extract
RUN tar -zxf /tmp/msoffice.tar.gz -C /opt/al/support/extract
RUN tar -zxf /tmp/cybozulib.tar.gz -C /opt/al/support/extract
RUN make -C /opt/al/support/extract/msoffice -j RELEASE=1

# Cleanup
RUN rm -rf /tmp

# Clone Extract service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_extract.git