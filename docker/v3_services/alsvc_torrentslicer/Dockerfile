FROM sgaroncse/v3_service_base_dev:3.3.6

ENV SERVICE_PATH alsvc_torrentslicer.TorrentSlicer

RUN pip install \
  bencode \
  humanfriendly \
  hurry.filesize

# Clone TorrentSlicer service code
WORKDIR /opt/al/al_services
RUN git clone -b prod_3.3 https://bitbucket.org/cse-assemblyline/alsvc_torrentslicer.git