#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Push core containers
docker push sgaroncse/elasticsearch
docker push sgaroncse/nginx-ssl
docker push sgaroncse/nginx-ssl-dev
docker push sgaroncse/riak-kv

# Push dev containers
docker push sgaroncse/assemblyline_dev
docker push sgaroncse/assemblyline_dev_py2

# Push service containers
docker push sgaroncse/v3_service_base_dev
docker push sgaroncse/alsvc_characterize

