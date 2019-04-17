FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_suricata.Suricata

RUN apt-get update && apt-get install -y \
  libpcre3 \
  libpcre3-dbg \
  libpcre3-dev \
  build-essential \
  autoconf \
  automake \
  libtool \
  libpcap-dev \
  libnet1-dev \
  libyaml-0-2 \
  libyaml-dev \
  zlib1g \
  zlib1g-dev \
  libcap-ng-dev \
  libcap-ng0 \
  make \
  libmagic-dev \
  libjansson-dev \
  libjansson4 \
  pkg-config \
  cargo \
  liblua5.1-dev \
  libnss3-dev

RUN pip install \
  simplejson \
  python-dateutil \
  suricata-update \
  awscli

# AWS S3 credentials
ENV AWS_ACCESS_KEY_ID=AKIAIIESFCKMSXUP6KWQ
ENV AWS_SECRET_ACCESS_KEY=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
ENV AWS_REGION=us-east-1

# Download the support file from Amazon S3
WORKDIR /tmp
RUN aws s3 suricata/suricata-4.1.2.tar.gz .

RUN tar -xzf suricata-4.1.2.tar.gz
WORKDIR /tmp/suricata-4.1.2

RUN ./configure --prefix=/usr/local/ --sysconfdir=/etc/ --localstatedir=/var/ --enable-python --enable-rust --enable-lua
RUN make
RUN make install 
RUN ldconfig 
RUN make install-full

RUN mkdir -p /etc/suricata
RUN chown -R al /etc/suricata
RUN mkdir -p /var/lib/suricata
RUN chown -R al /var/lib/suricata
RUN mkdir -p /var/log/suricata
RUN chown -R al /var/log/suricata

# Clone Suricata service code
WORKDIR /opt/al/al_services
RUN git clone https://bitbucket.org/cse-assemblyline/alsvc_suricata.git

RUN cp /opt/al/al_services/alsvc_suricata/conf/suricata.yaml /etc/suricata/
RUN chown al /etc/suricata/suricata.yaml

RUN sed -i.bak -e 's/__HOME_NET__/any/g' /etc/suricata/suricata.yaml

RUN suricata-update --no-test --url \["https:\/\/rules.emergingthreats.net\/open\/suricata\/emerging.rules.tar.gz"\]

RUN touch /etc/suricata/suricata-rules-update
RUN chown -R al /var/lib/suricata/
RUN chown al /etc/suricata/suricata-rules-update

RUN /usr/bin/gcc -o /opt/al/al_services/alsvc_suricata/stripe/stripe /opt/al/al_services/alsvc_suricata/stripe/stripe.c
RUN cp /opt/al/al_services/alsvc_suricata/stripe/stripe /usr/local/bin/stripe

# Cleanup
RUN rm -rf /tmp/suricata-4.1.2 /tmp/suricata-4.1.2.tar.gz