#!/bin/bash -ex

# Build core containers
(cd elasticsearch && docker build -t cccs/elasticsearch:8.3.3 .)
(cd nginx-ssl-frontend && docker build -t cccs/nginx-ssl-frontend .)
(cd minio && docker build -t cccs/minio .)

# Build default dev containers
(cd ../.. && docker build --no-cache -f assemblyline-base/docker/al_dev/Dockerfile -t cccs/assemblyline_dev:latest -t cccs/assemblyline_dev:4.2.3 .)
(cd ../.. && docker build --no-cache -f assemblyline-base/docker/al_management/Dockerfile -t cccs/assemblyline_management:latest -t cccs/assemblyline_management:4.2.3 .)
