# Dockerfile - python slim based, root mode, full agent + CTF toolset
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install apt packages (CTF/pentest tools + system essentials)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential git curl wget ca-certificates unzip zip \
    tzdata \
    net-tools iproute2 iputils-ping dnsutils \
    nmap tcpdump socat netcat-openbsd \
    ffuf binwalk jq file bsdmainutils vim-common \
    binutils strace ltrace gdb \
    yara libmagic1 libmagic-dev \
    ripgrep exiftool steghide \
    openssh-client openssl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*



# Attempt to install rizin (lightweight radare2 alternative, optional)
RUN set -eux; \
    apt-get update || true; \
    if apt-get install -y --no-install-recommends rizin; then \
      echo "✅ Installed rizin (radare2 alternative)"; \
    else \
      echo "⚠️ rizin not available, skipping (radare2 not installed)"; \
    fi; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

# Install Python packages (SDKs + helpers)
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel \
 && python3 -m pip install --no-cache-dir \
      requests urllib3 python-magic \
      openai anthropic r2pipe

# Create working directory and copy source
WORKDIR /workspace
COPY . /workspace

# Create venv at /root/.venv and install requirements (if any)
RUN python3 -m venv /root/.venv \
 && /root/.venv/bin/python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
 && if [ -f /workspace/requirements.txt ]; then /root/.venv/bin/python -m pip install --no-cache-dir -r /workspace/requirements.txt; fi

ENV PATH="/root/.venv/bin:${PATH}"

# Default behavior: run operatives.py if exists, else open bash
CMD ["bash", "-lc", "cd /workspace && if [ -f operatives.py ]; then python operatives.py; else exec bash; fi"]
