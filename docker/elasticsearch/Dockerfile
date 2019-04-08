FROM docker.elastic.co/elasticsearch/elasticsearch:6.7.0

ENV ES_JAVA_OPTS "-Xms1g -Xmx1g"

RUN sed -i -e "s/-Xms1g/# -Xms1g/g" \
-e "s/-Xmx1g/# -Xmx1g/g" config/jvm.options

CMD if [ $DISCOVERY_TYPE ] && [ `grep -q "discovery.type:" config/elasticsearch.yml` ]; then \
echo "discovery.type: $DISCOVERY_TYPE" >> config/elasticsearch.yml; fi && \
/usr/local/bin/docker-entrypoint.sh
