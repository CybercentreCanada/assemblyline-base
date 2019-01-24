FROM docker.elastic.co/elasticsearch/elasticsearch:6.4.2

ENV ES_JAVA_OPTS "-Xms1g -Xmx1g"

RUN sed -i -e "s/-Xms1g/# -Xms1g/g" \
-e "s/-Xmx1g/# -Xmx1g/g" config/jvm.options

CMD if [ $DISCOVERY_TYPE ]; then \
echo "discovery.type: $DISCOVERY_TYPE" >> config/elasticsearch.yml; fi && \
/usr/local/bin/docker-entrypoint.sh
