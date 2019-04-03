FROM docker.elastic.co/beats/metricbeat:6.7.0

USER root
COPY alv4/test/scripts/wait-for-it.sh /usr/share/metricbeat/wait-for-it.sh
RUN chmod +x /usr/share/metricbeat/wait-for-it.sh

ENTRYPOINT []
CMD ['/usr/local/bin/docker-entrypoint', '-e']