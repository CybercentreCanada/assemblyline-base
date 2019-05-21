FROM docker.elastic.co/elasticsearch/elasticsearch:7.1.0

ENV ES_JAVA_OPTS "-Xms1g -Xmx1g"

RUN sed -i -e "s/-Xms1g/# -Xms1g/g" \
-e "s/-Xmx1g/# -Xmx1g/g" config/jvm.options

COPY set_vars.sh /usr/share/elasticsearch/set_vars.sh

RUN chmod +x /usr/share/elasticsearch/set_vars.sh

CMD /usr/share/elasticsearch/set_vars.sh && /usr/local/bin/docker-entrypoint.sh
