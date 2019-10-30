#!/bin/bash -ex

# Push core containers
docker push sgaroncse/elasticsearch
docker push sgaroncse/apm-server
docker push sgaroncse/minio
docker push sgaroncse/nginx-ssl-bitbucket
docker push sgaroncse/nginx-ssl
docker push sgaroncse/nginx-ssl-dev

# Push dev containers
docker push cccs/assemblyline_dev
