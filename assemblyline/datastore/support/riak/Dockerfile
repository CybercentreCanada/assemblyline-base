FROM basho/riak-kv:2.1.4

# Default heap size
ENV SOLR_HEAP "-Xms1g -Xmx1g"

# Make sure riak.conf is ok for AL
RUN sed -i -e "s/anti_entropy = .*/anti_entropy = passive/g" \
-e "s/storage_backend = .*/storage_backend = leveldb/g" \
-e "s/127\.0\.0\.1:/0.0.0.0:/g" \
-e "s/leveldb.maximum_memory.percent = .*/leveldb.maximum_memory.percent = 50/g" \
-e "s/search = .*/search = on/g" \
/etc/riak/riak.conf

# Getting rid of the host paching behavior of the riak-cluster command
# so we can bind to 0.0.0.0
RUN sed -i -e "s/sed -i .*listener.*//g" /usr/lib/riak/riak-cluster.sh

# Expose ports
EXPOSE 8087
EXPOSE 8098
EXPOSE 8093

# Last minute patch to heap and run the cluster
CMD sed -i -e "s/-Xms1g -Xmx1g/$SOLR_HEAP/g" /etc/riak/riak.conf && \
/usr/lib/riak/riak-cluster.sh
