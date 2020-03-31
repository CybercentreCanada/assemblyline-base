#!/bin/bash -ex

# Build core containers
(cd elasticsearch && docker build -t sgaroncse/elasticsearch:7.6.0 .)
(cd nginx-ssl && docker build -t sgaroncse/nginx-ssl:1.17.5 .)
(cd minio && docker build -t sgaroncse/minio .)

# Build default dev containers
(cd ../.. && docker build -f assemblyline-base/docker/al_dev/Dockerfile -t cccs/assemblyline_dev:latest -t cccs/assemblyline_dev:4.0.17 .)
(cd ../.. && docker build -f assemblyline-base/docker/al_management/Dockerfile -t cccs/assemblyline_management:latest .)
