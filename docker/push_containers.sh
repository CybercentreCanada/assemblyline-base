#!/bin/bash -ex

# Push core containers
docker push sgaroncse/elasticsearch
docker push sgaroncse/apm-server
docker push sgaroncse/metricbeat
docker push sgaroncse/minio
docker push sgaroncse/nginx-ssl-bitbucket
docker push sgaroncse/nginx-ssl
docker push sgaroncse/nginx-ssl-dev
docker push sgaroncse/riak-kv

# Push dev containers
docker push sgaroncse/assemblyline_base
docker push sgaroncse/assemblyline_dev
docker push sgaroncse/assemblyline_dev_py2

# Push service containers
docker push sgaroncse/v3_service_base_dev
# docker push sgaroncse/alsvc_apivector
# docker push sgaroncse/alsvc_apkaye
# docker push sgaroncse/alsvc_beaver
# docker push sgaroncse/alsvc_cfmd
docker push sgaroncse/alsvc_characterize
# docker push sgaroncse/alsvc_cleaver
# docker push sgaroncse/alsvc_configdecoder
# docker push sgaroncse/alsvc_espresso
docker push sgaroncse/alsvc_extract
docker push sgaroncse/alsvc_frankenstrings
# docker push sgaroncse/alsvc_fsecure
# docker push sgaroncse/alsvc_iparse
# docker push sgaroncse/alsvc_metadefender
# docker push sgaroncse/alsvc_metapeek
# docker push sgaroncse/alsvc_nsrl
# docker push sgaroncse/alsvc_nsrl_db
# docker push sgaroncse/alsvc_oletools
docker push sgaroncse/alsvc_pdfid
# docker push sgaroncse/alsvc_peepdf
# docker push sgaroncse/alsvc_pefile
# docker push sgaroncse/alsvc_pixaxe
# docker push sgaroncse/alsvc_suricata
# docker push sgaroncse/alsvc_swiffer
# docker push sgaroncse/alsvc_sync
# docker push sgaroncse/alsvc_tagcheck
# docker push sgaroncse/alsvc_torrentslicer
# docker push sgaroncse/alsvc_unpacker
# docker push sgaroncse/alsvc_virustotal_dynamic
# docker push sgaroncse/alsvc_virustotal_static
# docker push sgaroncse/alsvc_yara

