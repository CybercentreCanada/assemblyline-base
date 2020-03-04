FROM python:3.7-slim-stretch

ARG version

# Make sure root account is locked so 'su' commands fail all the time
RUN passwd -l root

# Get required apt packages
RUN apt-get update \
  && apt-get install -yy build-essential libffi-dev libfuzzy-dev libmagic1 \
  && rm -rf /var/lib/apt/lists/*

# Install assemblyline base
RUN pip3 install "urllib3<1.25,>=1.21.1" && rm -rf ~/.cache/pip
RUN pip3 install assemblyline==$version && rm -rf ~/.cache/pip

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
RUN chmod 770 /var/lib/assemblyline
RUN chown assemblyline:assemblyline /var/lib/assemblyline

# Create assemblyline log directory
RUN mkdir -p /var/log/assemblyline
RUN chmod 770 /var/log/assemblyline
RUN chown assemblyline:assemblyline /var/log/assemblyline

# Switch to assemblyline user
USER assemblyline
WORKDIR /var/lib/assemblyline

CMD /bin/bash
