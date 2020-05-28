#!/bin/bash -ex

# Build core containers
(cd elasticsearch && docker build -t cccs/elasticsearch:7.7.0 .)
(cd nginx-ssl && docker build -t cccs/nginx-ssl .)
(cd minio && docker build -t cccs/minio .)

# Build default dev containers
(cd ../.. && docker build -f assemblyline-base/docker/al_dev/Dockerfile -t cccs/assemblyline_dev:latest -t cccs/assemblyline_dev:4.0.17 .)
(cd ../.. && docker build -f assemblyline-base/docker/al_management/Dockerfile -t cccs/assemblyline_management:latest .)
