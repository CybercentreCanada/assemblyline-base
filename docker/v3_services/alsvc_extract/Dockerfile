FROM sgaroncse/v3_service_base_dev:3.3.2

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
RUN mkdir -p /opt/al/support/extract
WORKDIR /opt/al/support/extract/
RUN aws s3 cp s3://assemblyline-support/msoffice.tar.gz .
RUN aws s3 cp s3://assemblyline-support/cybozulib.tar.gz .

# Extract the tar files and make msoffice
RUN tar -zxf msoffice.tar.gz
RUN tar -zxf cybozulib.tar.gz
WORKDIR /opt/al/support/extract/msoffice
RUN make -j RELEASE=1

# Clone Characterize service code
WORKDIR /opt/al/al_services

RUN git clone https://bitbucket.org/cse-assemblyline/alsvc_extract.git