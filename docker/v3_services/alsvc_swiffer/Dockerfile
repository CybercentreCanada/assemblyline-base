FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_swiffer.Swiffer

RUN apt-get update && apt-get install -y \
  libjpeg-dev

RUN pip install \
  Pillow==2.3.0 \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/rabcdasm.tar.gz /tmp
RUN aws s3 cp s3://assemblyline-support/pyswf-master-custom-patched.tgz /tmp

RUN mkdir -p /opt/al/support/swiffer
RUN tar xvzf /tmp/rabcdasm.tar.gz -C /opt/al/support/swiffer

RUN pip install \
  /tmp/pyswf-master-custom-patched.tgz

# Cleanup
RUN rm -rf /tmp

# Clone Swiffer service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_swiffer.git