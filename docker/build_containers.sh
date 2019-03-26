#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Build core containers
(cd elasticsearch && docker build -t sgaroncse/elasticsearch:6.4.2 .)
(cd nginx-ssl && docker build -t sgaroncse/nginx-ssl:4.0.0 -t sgaroncse/nginx-ssl:latest .)
(cd nginx-ssl-dev && docker build -t sgaroncse/nginx-ssl-dev:4.0.0 -t sgaroncse/nginx-ssl-dev:latest .)
(cd riak && docker build -t sgaroncse/riak-kv:2.1.4 .)

# Build default dev containers
(cd ../.. && docker build -f alv4/docker/al_dev/Dockerfile -t sgaroncse/assemblyline_dev:latest -t sgaroncse/assemblyline_dev:4.0.1 .)
(cd ../.. && docker build -f alv4/docker/al_dev_py2/Dockerfile -t sgaroncse/assemblyline_dev_py2:latest -t sgaroncse/assemblyline_dev_py2:4.0.1 .)

# Build services containers
(cd ../.. && docker build -f alv4/docker/v3_services/v3_service_base_dev/Dockerfile -t sgaroncse/v3_service_base_dev:latest -t sgaroncse/v3_service_base_dev:3.3.2 .)
(cd ../.. && docker build -f alv4/docker/v3_services/alsvc_characterize/Dockerfile -t sgaroncse/alsvc_characterize:latest -t sgaroncse/alsvc_characterize:3.3.1 .)
(cd ../.. && docker build -f alv4/docker/v3_services/alsvc_extract/Dockerfile -t sgaroncse/alsvc_extract:latest -t sgaroncse/alsvc_extract:3.3.0 .)
(cd ../.. && docker build -f alv4/docker/v3_services/alsvc_pdfid/Dockerfile -t sgaroncse/alsvc_pdfid:latest -t sgaroncse/alsvc_pdfid:3.3.0 .)

