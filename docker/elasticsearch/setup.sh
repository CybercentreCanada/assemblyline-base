#!/bin/bash -x

until curl --silent --fail -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_cluster/health
do
    echo "Waiting for elasticsearch to come online..."
    sleep 1
done

if [ $KIBANA_PASSWORD ]; then
    echo "Setting up kibana password..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/kibana/_password -d "{\"password\": \"$KIBANA_PASSWORD\"}"
    curl --silent -X PUT -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/kibana/_enable
fi
if [ $APM_PASSWORD ]; then
    echo "Setting up apm password..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/apm_system/_password -d "{\"password\": \"$APM_PASSWORD\"}"
    curl --silent -X PUT -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/apm_system/_enable
fi
if [ $BEATS_PASSWORD ]; then
    echo "Setting up beats password..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/beats_system/_password -d "{\"password\": \"$BEATS_PASSWORD\"}"
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/remote_monitoring_user/_password -d "{\"password\": \"$BEATS_PASSWORD\"}"
    curl --silent -X PUT -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/beats_system/_enable
    curl --silent -X PUT -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/remote_monitoring_user/_enable

fi
if [ $LOGSTASH_PASSWORD ]; then
    echo "Setting up logstash password..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/logstash_system/_password -d "{\"password\": \"$LOGSTASH_PASSWORD\"}"
    curl --silent -X PUT -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/logstash_system/_enable

fi

echo "Randomizing elastic's user password..."
curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/elastic/_password -d "{\"password\": \"`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c24`\"}"
