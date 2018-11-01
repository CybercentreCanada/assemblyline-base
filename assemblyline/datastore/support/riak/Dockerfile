FROM basho/riak-kv:2.1.4

ENV SOLR_HEAP "-Xms1g -Xmx1g"

RUN sed -i -e "s/anti_entropy = .*/anti_entropy = passive/g" \
-e "s/storage_backend = .*/storage_backend = leveldb/g" \
-e "s/leveldb.maximum_memory.percent = .*/leveldb.maximum_memory.percent = 50/g" \
-e "s/search = .*/search = on/g" \
/etc/riak/riak.conf

EXPOSE 8087
EXPOSE 8098
EXPOSE 8093

CMD sed -i -e "s/-Xms1g -Xmx1g/$SOLR_HEAP/g" /etc/riak/riak.conf && \
/usr/lib/riak/riak-cluster.sh
