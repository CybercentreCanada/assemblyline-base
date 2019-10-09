#!/bin/bash

until curl --silent --fail -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_cluster/health
do
    echo "Waiting for elasticsearch to come online..."
    sleep 1
done

if [ $KIBANA_PASSWORD ]; then
    echo "Setting up kibana password..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/kibana/_password -d "{\"password\": \"$KIBANA_PASSWORD\"}"
fi

if [ $APM_PASSWORD ]; then
    echo "Setting up apm password..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/role/apm -d "{\"cluster\":[\"manage_ilm\", \"manage_pipeline\"],\"indices\":[{\"names\":[\"apm-*\",\".ml-anomalies*\"],\"privileges\":[\"all\"],\"allow_restricted_indices\":false}],\"applications\":[],\"run_as\":[],\"metadata\":{}}"
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/apm -d "{\"password\": \"$APM_PASSWORD\",\"roles\":[\"apm_user\",\"apm_system\",\"kibana_system\",\"apm\"],\"full_name\":null,\"email\":null,\"metadata\":{}}"
fi

if [ $FILEBEAT_PASSWORD ]; then
    echo "Setting up filebeat password..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/role/filebeat -d "{\"cluster\":[\"manage_ilm\", \"manage_pipeline\"],\"indices\":[{\"names\":[\"filebeat-*\"],\"privileges\":[\"all\"],\"allow_restricted_indices\":false}],\"applications\":[],\"run_as\":[],\"metadata\":{}}"
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/filebeat -d "{\"password\": \"$FILEBEAT_PASSWORD\",\"roles\":[\"beats_system\",\"kibana_system\",\"filebeat\"],\"full_name\":null,\"email\":null,\"metadata\":{}}"
fi

if [ $METRICBEAT_PASSWORD ]; then
    echo "Setting up metricbeat password... (*WARNING: This has to be a superuser for now... :( )"
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/metricbeat -d "{\"password\": \"$METRICBEAT_PASSWORD\",\"roles\":[\"superuser\"],\"full_name\":null,\"email\":null,\"metadata\":{}}"
fi

if [ $AL_PASSWORD ]; then
    echo "Create assemblyline_system role..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/role/assemblyline_system -d "{\"cluster\":[],\"indices\":[{\"names\":[\"al_metrics_*\",\"alert\",\"cached_*\",\"emptyresult\",\"error\",\"file*\",\"heuristic\",\"result\",\"service*\",\"signature\",\"submission*\",\"user*\",\"vm\",\"workflow\"],\"privileges\":[\"all\"],\"allow_restricted_indices\":false}],\"applications\":[],\"run_as\":[],\"metadata\":{}}"

    echo "Create assemblyline user..."
    curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/assemblyline -d "{\"password\":\"$AL_PASSWORD\",\"roles\":[\"assemblyline_system\"],\"full_name\":null,\"email\":null,\"metadata\":{}}"
fi

if [ $SU_USERNAME ]; then
    if [ $SU_PASSWORD ]; then
        echo "Create super user $SU_USERNAME..."
        curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/$SU_USERNAME -d "{\"password\":\"$SU_PASSWORD\",\"roles\":[\"superuser\"],\"full_name\":null,\"email\":null,\"metadata\":{}}"
    fi
fi

if [ $K_USERNAME ]; then
    if [ $K_PASSWORD ]; then
        echo "Create kibana dashboard user $K_USERNAME..."
        curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/$K_USERNAME -d "{\"password\":\"$K_PASSWORD\",\"roles\":[\"kibana_user\",\"apm_user\",\"monitoring_user\"],\"full_name\":null,\"email\":null,\"metadata\":{}}"
    fi
fi

echo "Randomizing elastic's user password..."
curl --silent -X POST -H "Content-Type: application/json" -u elastic:$ELASTIC_PASSWORD http://$ELASTIC_HOST:9200/_security/user/elastic/_password -d "{\"password\": \"`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c24`\"}"
