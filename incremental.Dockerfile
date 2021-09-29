# This dockerfile only includes the minimal steps to build a package onto
# a periodic root image
ARG build_image
ARG base
ARG tag
FROM $build_image AS builder
ARG version

# Install assemblyline base (setup.py is just a file we know exists so the command
# won't fail if dist isn't there. The dist* copies in any dist directory only if it exists.)
COPY setup.py dist* dist/
RUN pip install --no-cache-dir -f dist/ -U --user assemblyline==$version && rm -rf ~/.cache/pip

FROM $base:$tag
ARG version
ARG version_tag=${version}

# Install assemblyline base
COPY --chown=assemblyline:assemblyline --from=builder /root/.local /var/lib/assemblyline/.local
ENV PATH=/var/lib/assemblyline/.local/bin:$PATH
ENV ASSEMBLYLINE_VERSION=${version}
ENV ASSEMBLYLINE_IMAGE_TAG=${version_tag}

# Switch to assemblyline user
USER assemblyline
WORKDIR /var/lib/assemblyline
CMD /bin/bash
