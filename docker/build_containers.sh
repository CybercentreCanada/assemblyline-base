#!/bin/bash -ex

# Build core containers
(cd elasticsearch && docker build -t sgaroncse/elasticsearch:7.6.0 .)
(cd nginx-ssl && docker build -t sgaroncse/nginx-ssl:1.17.5 .)
(cd minio && docker build -t sgaroncse/minio .)

# Build default dev containers
(cd ../.. && docker build -f alv4/docker/al_dev/Dockerfile -t cccs/assemblyline_dev:latest -t cccs/assemblyline_dev:4.0.11 .)
(cd ../.. && docker build -f alv4/docker/al_management/Dockerfile -t cccs/assemblyline_management:latest .)
