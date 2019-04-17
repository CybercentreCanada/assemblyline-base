FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_oletools.Oletools

RUN pip install \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/oletools-0.53.1.tar.gz /tmp

RUN pip install \
  /tmp/oletools-0.53.1.tar.gz

# Clone Oletools service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_oletools.git

RUN python alv4/assemblyline/common/yara/yara_importer.py -f -s /opt/al/al_services/alsvc_oletools/yara_rules/oletools_sigs.yar

