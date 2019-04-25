#!/bin/bash -ex

# Build core containers
(cd elasticsearch && docker build -t sgaroncse/elasticsearch:7.0.0 .)
(cd apm-server && docker build -t sgaroncse/apm-server:7.0.0 .)
(cd ../.. && docker build -f alv4/docker/metricbeat/Dockerfile -t sgaroncse/metricbeat:7.0.0 .)
(cd nginx-ssl && docker build -t sgaroncse/nginx-ssl:1.15.10-2 .)
(cd nginx-ssl-dev && docker build -t sgaroncse/nginx-ssl-dev:1.15.10-1 .)
(cd riak && docker build -t sgaroncse/riak-kv:2.1.4 .)

# Build default dev containers
(cd ../.. && docker build -f alv4/docker/al_dev/Dockerfile -t sgaroncse/assemblyline_dev:latest -t sgaroncse/assemblyline_dev:4.0.4 .)
(cd ../.. && docker build -f alv4/docker/al_dev_py2/Dockerfile -t sgaroncse/assemblyline_dev_py2:latest -t sgaroncse/assemblyline_dev_py2:4.0.4 .)

# Build service containers
SERVICE_VERSION=3.3.5
(cd ../.. && docker build -f alv4/docker/v3_services/v3_service_base_dev/Dockerfile -t sgaroncse/v3_service_base_dev:latest -t sgaroncse/v3_service_base_dev:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_apivector/Dockerfile -t sgaroncse/alsvc_apivector:latest -t sgaroncse/alsvc_apivector:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_apkaye/Dockerfile -t sgaroncse/alsvc_apkaye:latest -t sgaroncse/alsvc_apkaye:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_beaver/Dockerfile -t sgaroncse/alsvc_beaver:latest -t sgaroncse/alsvc_beaver:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_cfmd/Dockerfile -t sgaroncse/alsvc_cfmd:latest -t sgaroncse/alsvc_cfmd:${SERVICE_VERSION} .)
(cd ../.. && docker build -f alv4/docker/v3_services/alsvc_characterize/Dockerfile -t sgaroncse/alsvc_characterize:latest -t sgaroncse/alsvc_characterize:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_cleaver/Dockerfile -t sgaroncse/alsvc_cleaver:latest -t sgaroncse/alsvc_cleaver:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_configdecoder/Dockerfile -t sgaroncse/alsvc_configdecoder:latest -t sgaroncse/alsvc_configdecoder:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_espresso/Dockerfile -t sgaroncse/alsvc_espresso:latest -t sgaroncse/alsvc_espresso:${SERVICE_VERSION} .)
(cd ../.. && docker build -f alv4/docker/v3_services/alsvc_extract/Dockerfile -t sgaroncse/alsvc_extract:latest -t sgaroncse/alsvc_extract:${SERVICE_VERSION} .)
(cd ../.. && docker build -f alv4/docker/v3_services/alsvc_frankenstrings/Dockerfile -t sgaroncse/alsvc_frankenstrings:latest -t sgaroncse/alsvc_frankenstrings:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_fsecure/Dockerfile -t sgaroncse/alsvc_fsecure:latest -t sgaroncse/alsvc_fsecure:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_iparse/Dockerfile -t sgaroncse/alsvc_iparse:latest -t sgaroncse/alsvc_iparse:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_lastline/Dockerfile -t sgaroncse/alsvc_lastline:latest -t sgaroncse/alsvc_lastline:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_metadefender/Dockerfile -t sgaroncse/alsvc_metadefender:latest -t sgaroncse/alsvc_metadefender:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_metapeek/Dockerfile -t sgaroncse/alsvc_metapeek:latest -t sgaroncse/alsvc_metapeek:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_nsrl/Dockerfile -t sgaroncse/alsvc_nsrl:latest -t sgaroncse/alsvc_nsrl:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_nsrl_db/Dockerfile -t sgaroncse/alsvc_nsrl_db:latest -t sgaroncse/alsvc_nsrl_db:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_oletools/Dockerfile -t sgaroncse/alsvc_oletools:latest -t sgaroncse/alsvc_oletools:${SERVICE_VERSION} .)
(cd ../.. && docker build -f alv4/docker/v3_services/alsvc_pdfid/Dockerfile -t sgaroncse/alsvc_pdfid:latest -t sgaroncse/alsvc_pdfid:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_peepdf/Dockerfile -t sgaroncse/alsvc_peepdf:latest -t sgaroncse/alsvc_peepdf:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_pefile/Dockerfile -t sgaroncse/alsvc_pefile:latest -t sgaroncse/alsvc_pefile:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_pixaxe/Dockerfile -t sgaroncse/alsvc_pixaxe:latest -t sgaroncse/alsvc_pixaxe:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_suricata/Dockerfile -t sgaroncse/alsvc_suricata:latest -t sgaroncse/alsvc_suricata:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_swiffer/Dockerfile -t sgaroncse/alsvc_swiffer:latest -t sgaroncse/alsvc_swiffer:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_sync/Dockerfile -t sgaroncse/alsvc_sync:latest -t sgaroncse/alsvc_sync:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_tagcheck/Dockerfile -t sgaroncse/alsvc_tagcheck:latest -t sgaroncse/alsvc_tagcheck:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_torrentslicer/Dockerfile -t sgaroncse/alsvc_torrentslicer:latest -t sgaroncse/alsvc_torrentslicer:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_unpacker/Dockerfile -t sgaroncse/alsvc_unpacker:latest -t sgaroncse/alsvc_unpacker:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_virustotal_dynamic/Dockerfile -t sgaroncse/alsvc_virustotal_dynamic:latest -t sgaroncse/alsvc_virustotal_dynamic:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_virustotal_static/Dockerfile -t sgaroncse/alsvc_virustotal_static:latest -t sgaroncse/alsvc_virustotal_static:${SERVICE_VERSION} .)
# (cd ../.. && docker build -f alv4/docker/v3_services/alsvc_yara/Dockerfile -t sgaroncse/alsvc_yara:latest -t sgaroncse/alsvc_yara:${SERVICE_VERSION} .)

