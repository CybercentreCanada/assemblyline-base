#!/bin/bash -ex

# Build core containers
(cd elasticsearch && docker build -t sgaroncse/elasticsearch:7.0.0 .)
(cd apm-server && docker build -t sgaroncse/apm-server:7.0.0 .)
(cd ../.. && docker build -f alv4/docker/metricbeat/Dockerfile -t sgaroncse/metricbeat:7.0.0 .)
(cd nginx-ssl-bitbucket && docker build -t sgaroncse/nginx-ssl-bitbucket:1.15.10-1 .)
(cd nginx-ssl && docker build -t sgaroncse/nginx-ssl:1.15.10-3 .)
(cd nginx-ssl-dev && docker build -t sgaroncse/nginx-ssl-dev:1.15.10-2 .)
(cd minio && docker build -t sgaroncse/minio .)

# Build default dev containers
(cd ../.. && docker build -f alv4/docker/al_base/Dockerfile -t sgaroncse/assemblyline_base:latest -t sgaroncse/assemblyline_base:4.0.0 .)
(cd ../.. && docker build -f alv4/docker/al_dev/Dockerfile -t sgaroncse/assemblyline_dev:latest -t sgaroncse/assemblyline_dev:4.0.5 .)
