# NOTE: to build this container you must be in a directory where assemblyline-base, assemblyline-ui,
# assemblyline-core, assemblyline-service-server and assemblyline-service-client code is checked out
FROM python:3.14-slim-trixie

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline \
    /var/cache/assemblyline \
    /var/lib/assemblyline/flowjs \
    /var/lib/assemblyline/bundling \
    /var/log/assemblyline \
    /opt/alv4

# Create Assemblyline user
RUN useradd -b /var/lib -U -m assemblyline

# Create assemblyline config directory
RUN chmod 750 /etc/assemblyline
RUN chown root:assemblyline /etc/assemblyline

# Create assemblyline cache directory
RUN chmod 770 /var/cache/assemblyline
RUN chown assemblyline:assemblyline /var/cache/assemblyline

# Create assemblyline home directory
RUN chmod 750 /var/lib/assemblyline
RUN chown assemblyline:assemblyline /var/lib/assemblyline

# Create assemblyline log directory
RUN chmod 770 /var/log/assemblyline
RUN chown assemblyline:assemblyline /var/log/assemblyline

# Create assemblyline local directory for user-specific installations
RUN mkdir -p /var/lib/assemblyline/.local/ && chown assemblyline:assemblyline -R /var/lib/assemblyline/.local/
RUN mkdir -p /opt/al_service && chown assemblyline:assemblyline -R /opt/al_service

WORKDIR /opt/alv4

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-service-server:/opt/alv4/assemblyline-service-client:/opt/alv4/assemblyline_client:/opt/alv4/assemblyline-ui:/opt/alv4/assemblyline-v4-service:/opt/al_service

COPY assemblyline-base assemblyline-base
COPY assemblyline-core assemblyline-core
COPY assemblyline-ui assemblyline-ui
COPY assemblyline_client assemblyline_client
COPY assemblyline-v4-service assemblyline-v4-service
COPY assemblyline-base/docker/compile_pkglist.txt compile_pkglist.txt
COPY assemblyline-base/docker/required_pkglist.txt required_pkglist.txt

# Install Assemblyline packages in editable mode
RUN apt-get update -yy && apt-get -yy upgrade \
    # Install system packages to compile some Python dependencies
    && apt-get install --no-install-recommends -y $(grep -vE "^\s*(#|$)" compile_pkglist.txt | tr "\n" " ") \
    # Install required packages that are needed at runtime and compile time
    && apt-get install --no-install-recommends -y $(grep -vE "^\s*(#|$)" required_pkglist.txt | tr "\n" " ") \
    # Update pip to the latest version
    && pip install --upgrade pip \
    # Install Assemblyline packages in editable mode
    && pip install --no-warn-script-location \
        -e ./assemblyline-base[test] \
        -e ./assemblyline-core[test] \
        -e ./assemblyline-ui[test,socketio] \
        -e ./assemblyline_client[test] \
        -e ./assemblyline-v4-service[test] \
    # Clean up installed Assemblyline packages
    && pip uninstall -y assemblyline-base assemblyline-core assemblyline-ui assemblyline_client assemblyline-v4-service \
    # Remove system packages used for building Python dependencies
    && apt-get purge -y $(grep -vE "^\s*(#|$)" compile_pkglist.txt | tr "\n" " ") && apt-get autoremove -y \
    # Remove pip cache and apt lists
    && rm -rf /root/.cache/pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/al_service
