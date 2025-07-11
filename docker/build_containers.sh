#!/bin/bash -ex

# Build core containers
(cd nginx-ssl-frontend && docker build -t cccs/nginx-ssl-frontend .)
(cd nginx-ssl-frontend:mui5 && docker build -t cccs/nginx-ssl-frontend:mui5 .)
(cd minio && docker build -t cccs/minio .)

# Build default dev containers
(cd ../.. && docker build --no-cache -f assemblyline-base/docker/al_dev/Dockerfile -t cccs/assemblyline_dev:latest -t cccs/assemblyline_dev:4.6.1 .)
(cd ../.. && docker build --no-cache -f assemblyline-base/docker/al_management/Dockerfile -t cccs/assemblyline_management:latest -t cccs/assemblyline_management:4.6.1 .)
