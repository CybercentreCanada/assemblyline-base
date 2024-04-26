FROM python:3.11-slim-bookworm AS base

# Upgrade packages
RUN apt-get update && apt-get -yy upgrade && rm -rf /var/lib/apt/lists/*

# Get required apt packages
RUN apt-get update && apt-get install -yy libffi8 libfuzzy2 libmagic1 && rm -rf /var/lib/apt/lists/*

# Make sure root account is locked so 'su' commands fail all the time
RUN passwd -l root

FROM base AS builder
ARG version
ARG version_tag=${version}

# Get required apt packages
RUN apt-get update \
  && apt-get install -yy build-essential libffi-dev libfuzzy-dev \
  && rm -rf /var/lib/apt/lists/*

# Install assemblyline base (setup.py is just a file we know exists so the command
# won't fail if dist isn't there. The dist* copies in any dist directory only if it exists.)
COPY setup.py dist* dist/
RUN pip install --no-cache-dir --no-warn-script-location -f dist/ --user assemblyline==$version && rm -rf ~/.cache/pip
RUN chmod 750 /root/.local/lib/python3.11/site-packages

FROM base

# Add assemblyline user
RUN useradd -b /var/lib -U -m assemblyline

# Create assemblyline config directory
RUN mkdir -p /etc/assemblyline
RUN chmod 750 /etc/assemblyline
RUN chown root:assemblyline /etc/assemblyline

# Create assemblyline cache directory
RUN mkdir -p /var/cache/assemblyline
RUN chmod 770 /var/cache/assemblyline
RUN chown assemblyline:assemblyline /var/cache/assemblyline

# Create assemblyline home directory
RUN mkdir -p /var/lib/assemblyline
RUN chmod 750 /var/lib/assemblyline
RUN chown assemblyline:assemblyline /var/lib/assemblyline

# Create assemblyline log directory
RUN mkdir -p /var/log/assemblyline
RUN chmod 770 /var/log/assemblyline
RUN chown assemblyline:assemblyline /var/log/assemblyline

# Install assemblyline base
COPY --chown=assemblyline:assemblyline --from=builder /root/.local /var/lib/assemblyline/.local
ENV PATH=/var/lib/assemblyline/.local/bin:$PATH
ENV PYTHONPATH=/var/lib/assemblyline/.local/lib/python3.11/site-packages
ENV ASSEMBLYLINE_VERSION=${version}
ENV ASSEMBLYLINE_IMAGE_TAG=${version_tag}

# Switch to assemblyline user
USER assemblyline
WORKDIR /var/lib/assemblyline
CMD /bin/bash
