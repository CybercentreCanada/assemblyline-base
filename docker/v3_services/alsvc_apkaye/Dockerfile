FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_apkaye.APKaye

RUN apt-get update && apt-get install \
  libc6-i386 \
  lib32z1 \
  lib32gcc1 \
  unzip

RUN pip install \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

RUN mkdir -p /opt/al/support/apkaye

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/apktool_2.0.3.jar /opt/al/support/apkaye
RUN aws s3 cp s3://assemblyline-support/dex-tools-2.0.zip /tmp
RUN aws s3 cp s3://assemblyline-support/aapt.tgz /tmp

RUN unzip -o /tmp/dex-tools-2.0.zip -d /tmp
RUN cp -R /tmp/dex2jar-2.0/ /opt/al/support/apkaye/
RUN chmod +x /opt/al/support/apkaye/dex2jar-2.0/*.sh

RUN tar -zxf /tmp/aapt.tgz -C /tmp
RUN cp -R /tmp/aapt /opt/al/support/apkaye

# Cleanup
RUN rm -rf /tmp

# Clone APKaye service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_apkaye.git
