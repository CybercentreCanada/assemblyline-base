FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_espresso.Espresso

RUN pip install \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

RUN mkdir -p /opt/al/support/cfr

# Download the support files from Amazon S3
RUN aws s3 cp s3://assemblyline-support/cfr_0_125.jar /opt/al/support/cfr
RUN aws s3 cp s3://assemblyline-support/jdk-8u72-linux-x64.tar.gz /tmp
RUN aws s3 cp s3://assemblyline-support/oracle-java8-installer_8u72+8u71arm-1-webupd8-0_all.deb /tmp
RUN aws s3 cp s3://assemblyline-support/oracle-java8-set-default_8u72+8u71arm-1-webupd8-0_all.deb /tmp

RUN DEBIAN_FRONTEND=noninteractive apt-get -y -q remove openjdk-8-jre-headless

RUN apt-get update && apt-get install \
  java-common

RUN mkdir /var/cache/oracle-jdk8-installer
RUN ln -s /tmp/jdk-8u72-linux-x64.tar.gz /var/cache/oracle-jdk8-installer/jdk-8u72-linux-x64.tar.gz
RUN echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo /usr/bin/debconf-set-selections
RUN dpkg -i /tmp/oracle-java8-installer_8u72+8u71arm-1-webupd8-0_all.deb
RUN dpkg -i /tmp/oracle-java8-set-default_8u72+8u71arm-1-webupd8-0_all.deb

# Clone Espresso service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_espresso.git
