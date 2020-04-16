#!/bin/bash -ex

# Push core containers
docker push cccs/elasticsearch
docker push cccs/minio
docker push cccs/nginx-ssl

# Push dev containers
docker push cccs/assemblyline_dev
docker push cccs/assemblyline_management
