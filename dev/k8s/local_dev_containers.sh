#!/bin/bash -ex

# Script assumes running from context of alv4 to pull in base, core, service-server, client, ui dirs for main container build

echo "Building $1"

# Build & push main container
(docker build . -t localhost:32000/cccs/assemblyline:$1 -f assemblyline-base/dev/k8s/local_dev.Dockerfile)
(docker push localhost:32000/cccs/assemblyline:$1)


# Build core containers
(docker tag localhost:32000/cccs/assemblyline:$1 localhost:32000/cccs/assemblyline-core:$1)
(docker build . -t localhost:32000/cccs/assemblyline-ui:$1 -f assemblyline-base/dev/k8s/ui.Dockerfile --build-arg build_no=$1)
(docker build . -t localhost:32000/cccs/assemblyline-socketio:$1 -f assemblyline-base/dev/k8s/socketio.Dockerfile --build-arg build_no=$1)
(docker build . -t localhost:32000/cccs/assemblyline-service-server:$1 -f assemblyline-base/dev/k8s/service-server.Dockerfile --build-arg build_no=$1)

# Push core to local registry
(docker push localhost:32000/cccs/assemblyline-core:$1)
(docker push localhost:32000/cccs/assemblyline-ui:$1)
(docker push localhost:32000/cccs/assemblyline-socketio:$1)
(docker push localhost:32000/cccs/assemblyline-service-server:$1)
