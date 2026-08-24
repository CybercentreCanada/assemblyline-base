FROM python:3.11-slim-bookworm

# Make sure root account is locked so 'su' commands fail all the time
RUN passwd -l root

# Upgrade packages
RUN apt-get update && apt-get -yy upgrade && rm -rf /var/lib/apt/lists/*

# Get required apt packages
RUN apt-get update && apt-get install -yy build-essential libssl-dev libffi-dev libfuzzy-dev libldap2-dev libsasl2-dev libmagic1 && rm -rf /var/lib/apt/lists/*

# Add assemblyline user
RUN useradd -s /bin/bash -b /var/lib -U -m assemblyline

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

# Create the assemblyline venv
RUN python -m venv /var/lib/assemblyline/venv

# Install packages in the venv
RUN /bin/bash -c "source /var/lib/assemblyline/venv/bin/activate && pip install --no-warn-script-location --no-cache-dir --upgrade pip wheel && pip install --no-warn-script-location --no-cache-dir assemblyline assemblyline_core assemblyline_ui assemblyline-client ipython jupyter"

# Setup venv when bash is launched
RUN echo "source /var/lib/assemblyline/venv/bin/activate" >> /var/lib/assemblyline/.bashrc

RUN mkdir -p /var/lib/assemblyline/jupyter
RUN mkdir -p /var/lib/assemblyline/.jupyter
RUN touch /var/lib/assemblyline/.jupyter/jupyter_notebook_config.py
RUN <<EOF cat > /var/lib/assemblyline/.jupyter/jupyter_notebook_config.py
import os
from jupyter_server.auth import passwd
nb_password = os.getenv("NB_PASSWORD")
if not nb_password:
    raise RuntimeError("NB_PASSWORD must be set")
c.NotebookApp.password = passwd(nb_password)
c.NotebookApp.allow_remote_access = True
c.NotebookApp.base_url = "/notebook/"
EOF

WORKDIR /var/lib/assemblyline

CMD /bin/bash -c "source /var/lib/assemblyline/venv/bin/activate && (cd /var/lib/assemblyline/jupyter && jupyter notebook -y --no-browser --ip=*)"
