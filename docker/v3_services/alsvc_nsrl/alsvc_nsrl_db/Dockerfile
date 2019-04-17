FROM postgres:11.2

RUN apt-get update && apt-get install -y \
  wget

RUN wget -P /tmp https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/RDS_modern.iso

# Clone NSRL service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_nsrl.git

RUN chmod +x /opt/al/al_services/alsvc_nsrl/db/install-postgres.sh
RUN sh /opt/al/al_services/alsvc_nsrl/db/install-postgres.sh -y
COPY postgresql.conf /etc/postgresql/9.3/main/postgresql.conf
COPY pg_hba.conf /etc/postgresql/9.3/main/pg_hba.conf
RUN postgres ./opt/al/al_services/alsvc_nsrl/db/create-nsrl.sh guest guest
RUN /opt/al/al_services/alsvc_nsrl/db/load-nsrl.sh 2.64 /tmp/RDS_modern.iso
RUN /opt/al/al_services/alsvc_nsrl/db/replace-views.sh 2.64 guest