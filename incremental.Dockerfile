# This dockerfile only includes the minimal steps to build a package onto
# a periodic root image
ARG build_image
FROM $build_image AS builder
ARG version

# Install assemblyline base (setup.py is just a file we know exists so the command
# won't fail if dist isn't there. The dist* copies in any dist directory only if it exists.)
RUN touch /tmp/before-pip
COPY setup.py dist* dist/
RUN pip install --no-cache-dir -f dist/ -U --user assemblyline==$version && rm -rf ~/.cache/pip

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

ARG base
ARG tag
FROM $base:$tag

# Install assemblyline base
COPY --chown=assemblyline:assemblyline --from=builder /root/.local /var/lib/assemblyline/.local
ENV PATH=/var/lib/assemblyline/.local/bin:$PATH

# Switch to assemblyline user
USER assemblyline
WORKDIR /var/lib/assemblyline
CMD /bin/bash
