#!/bin/bash -ex

# Script assumes running from context of alv4 to pull in base, core, service-server, client, ui dirs for main container build

echo "Building $1"

# Build & push main container
(docker build . -t localhost:32000/cccs/assemblyline:$1 -f assemblyline-base/dev/k8s/local_dev.Dockerfile)
(docker tag localhost:32000/cccs/assemblyline:$1 localhost:32000/cccs/assemblyline:latest)

# Build core containers
cd assemblyline-base/dev/k8s/
(docker tag localhost:32000/cccs/assemblyline:$1 localhost:32000/cccs/assemblyline-core:$1)
(docker build . -t localhost:32000/cccs/assemblyline-ui:$1 -f ui.Dockerfile --build-arg build_no=$1)
(docker build . -t localhost:32000/cccs/assemblyline-socketio:$1 -f socketio.Dockerfile --build-arg build_no=$1)
(docker build . -t localhost:32000/cccs/assemblyline-service-server:$1 -f service-server.Dockerfile --build-arg build_no=$1)

# Push core to local registry
(docker push localhost:32000/cccs/assemblyline-core:$1)
(docker push localhost:32000/cccs/assemblyline-ui:$1)
(docker push localhost:32000/cccs/assemblyline-socketio:$1)
(docker push localhost:32000/cccs/assemblyline-service-server:$1)

# Build service-base
(docker build . -t cccs/assemblyline-v4-service-base:$1 -f service-base.Dockerfile --build-arg build_no=$1)
(docker tag cccs/assemblyline-v4-service-base:$1 cccs/assemblyline-v4-service-base:latest)
