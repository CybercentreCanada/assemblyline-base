#!/bin/bash -ex

if [ $DISCOVERY_TYPE ]; then
    grep -q 'discovery.type:' config/elasticsearch.yml || echo "discovery.type: $DISCOVERY_TYPE" >> config/elasticsearch.yml
fi

if [ $NODE_NAME ]; then
    grep -q 'node.name:' config/elasticsearch.yml || echo "node.name: $NODE_NAME" >> config/elasticsearch.yml
fi

if [ $MASTER_NODE ]; then
    grep -q 'cluster.initial_master_nodes:' config/elasticsearch.yml || echo "cluster.initial_master_nodes: $MASTER_NODE" >> config/elasticsearch.yml
fi

if [ $CLUSTER_NAME ]; then
    grep -q 'cluster.name:' config/elasticsearch.yml || echo "cluster.name: $CLUSTER_NAME" >> config/elasticsearch.yml
fi

if [ $ELASTIC_PASSWORD ]; then
    grep -q 'xpack.security.enabled:' config/elasticsearch.yml || echo "xpack.security.enabled: true" >> config/elasticsearch.yml
fi