# NOTE: to build this container you must be in a directory where assemblyline-base, assemblyline-ui,
# assemblyline-core, assemblyline-service-server and assemblyline-service-client code is checked out
FROM python:3.14-slim-trixie

# Create Assemblyline source directory
RUN mkdir -p /etc/assemblyline
RUN mkdir -p /var/cache/assemblyline
RUN mkdir -p /var/lib/assemblyline
RUN mkdir -p /var/lib/assemblyline/flowjs
RUN mkdir -p /var/lib/assemblyline/bundling
RUN mkdir -p /var/log/assemblyline
RUN mkdir -p /opt/alv4
WORKDIR /opt/alv4

# Setup environment varibles
ENV PYTHONPATH /opt/alv4/assemblyline-base:/opt/alv4/assemblyline-core:/opt/alv4/assemblyline-service-server:/opt/alv4/assemblyline-service-client:/opt/alv4/assemblyline_client:/opt/alv4/assemblyline-ui

COPY assemblyline-base assemblyline-base
COPY assemblyline-core assemblyline-core
COPY assemblyline-ui assemblyline-ui
COPY assemblyline_client assemblyline_client
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
    # Upgrade xmlsec to the latest version
    && pip install --upgrade xmlsec \
    # Install Assemblyline packages in editable mode
    && pip install --no-warn-script-location \
        -e ./assemblyline-base[test] \
        -e ./assemblyline-core[test] \
        -e ./assemblyline-ui[test,socketio] \
        -e ./assemblyline_client[test] \
    # Clean up installed Assemblyline packages
    && pip uninstall -y assemblyline-base assemblyline-core assemblyline-ui assemblyline_client \
    # Remove system packages used for building Python dependencies
    && apt-get purge -y $(grep -vE "^\s*(#|$)" compile_pkglist.txt | tr "\n" " ") && apt-get autoremove -y \
    # Remove pip cache and apt lists
    && rm -rf /root/.cache/pip \
    && rm -rf /var/lib/apt/lists/*
