#!/bin/bash -ex

# Push core containers
docker push cccs/elasticsearch --all-tags
docker push cccs/minio --all-tags
docker push cccs/nginx-ssl-frontend --all-tags

# Push dev containers
docker push cccs/assemblyline_dev --all-tags
docker push cccs/assemblyline_management --all-tags
