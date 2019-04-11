FROM docker.elastic.co/apm/apm-server:7.0.0

USER root

RUN sed -i -e 's/\["elasticsearch:9200"\]/"${ES_HOSTS}"/g' /usr/share/apm-server/apm-server.yml

USER apm-server
