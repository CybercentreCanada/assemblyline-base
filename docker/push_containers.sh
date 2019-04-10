#!/bin/bash -ex

# Push core containers
docker push sgaroncse/elasticsearch
docker push sgaroncse/apm-server
docker push sgaroncse/metricbeat
docker push sgaroncse/nginx-ssl
docker push sgaroncse/nginx-ssl-dev
docker push sgaroncse/riak-kv

# Push dev containers
docker push sgaroncse/assemblyline_dev
docker push sgaroncse/assemblyline_dev_py2

# Push service containers
docker push sgaroncse/v3_service_base_dev
docker push sgaroncse/alsvc_characterize
docker push sgaroncse/alsvc_extract
docker push sgaroncse/alsvc_pdfid

