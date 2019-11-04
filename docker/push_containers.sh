#!/bin/bash -ex

# Push core containers
docker push sgaroncse/elasticsearch
docker push sgaroncse/minio
docker push sgaroncse/nginx-ssl

# Push dev containers
docker push cccs/assemblyline_dev
docker push cccs/assemblyline_management
