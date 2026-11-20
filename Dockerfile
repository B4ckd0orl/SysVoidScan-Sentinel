# ============================================================================
# SysVoidScan - Web Security Testing Scanner - Docker Image
# Multi-stage build optimized for scanning capabilities
# ============================================================================

# -------------------------- Stage 1: Base System ----------------------------
FROM kalilinux/kali-rolling AS base

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    GOPATH=/opt/go \
    PATH="${PATH}:/opt/go/bin:/usr/local/go/bin"

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        nmap \
        whatweb \
        hydra \
        wpscan \
        kerbrute \
        ldap-utils \
        impacket-scripts \
        gobuster \
        sqlmap \
        curl \
        wget \
        git \
        python3 \
        python3-pip \
        python3-venv \
        ruby \
        ruby-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        unzip \
        ca-certificates \
        gnupg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -------------------------- Stage 2: Go Tools --------------------------------
FROM base AS gotools

ENV GOPATH=/opt/go \
    GOBIN=/opt/go/bin

RUN mkdir -p /opt/go/bin && \
    go_bin="${GOBIN}" && \
    # subfinder
    echo "[+] Installing subfinder..." && \
    LATEST_SUBFINDER=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
    curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/${LATEST_SUBFINDER}/subfinder_${LATEST_SUBFINDER#v}_linux_amd64.zip" -o /tmp/subfinder.zip && \
    unzip -o /tmp/subfinder.zip -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder "${go_bin}/subfinder" && \
    chmod +x "${go_bin}/subfinder" && \
    rm -rf /tmp/subfinder /tmp/subfinder.zip && \
    # httpx
    echo "[+] Installing httpx..." && \
    LATEST_HTTPX=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
    curl -sL "https://github.com/projectdiscovery/httpx/releases/download/${LATEST_HTTPX}/httpx_${LATEST_HTTPX#v}_linux_amd64.zip" -o /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /tmp/httpx && \
    mv /tmp/httpx/httpx "${go_bin}/httpx" && \
    chmod +x "${go_bin}/httpx" && \
    rm -rf /tmp/httpx /tmp/httpx.zip && \
    # katana
    echo "[+] Installing katana..." && \
    LATEST_KATANA=$(curl -s https://api.github.com/repos/projectdiscovery/katana/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
    curl -sL "https://github.com/projectdiscovery/katana/releases/download/${LATEST_KATANA}/katana_${LATEST_KATANA#v}_linux_amd64.zip" -o /tmp/katana.zip && \
    unzip -o /tmp/katana.zip -d /tmp/katana && \
    mv /tmp/katana/katana "${go_bin}/katana" && \
    chmod +x "${go_bin}/katana" && \
    rm -rf /tmp/katana /tmp/katana.zip && \
    # dalfox
    echo "[+] Installing dalfox..." && \
    LATEST_DALFOX=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
    curl -sL "https://github.com/hahwul/dalfox/releases/download/${LATEST_DALFOX}/dalfox_${LATEST_DALFOX#v}_linux_amd64.zip" -o /tmp/dalfox.zip && \
    unzip -o /tmp/dalfox.zip -d /tmp/dalfox && \
    mv /tmp/dalfox/dalfox "${go_bin}/dalfox" && \
    chmod +x "${go_bin}/dalfox" && \
    rm -rf /tmp/dalfox /tmp/dalfox.zip

# -------------------------- Stage 3: Python Dependencies ---------------------
FROM base AS pythondeps

WORKDIR /tmp
COPY requirements.txt .
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# -------------------------- Stage 4: Final Image ----------------------------
FROM base AS final

LABEL maintainer="afsh4ck" \
      version="2.0.0" \
      description="SysVoidScan - Web Security Testing Scanner - Modular Edition" \
      org.opencontainers.image.source="https://github.com/afsh4ck/sysvoidscan" \
      org.opencontainers.image.title="SysVoidScan" \
      org.opencontainers.image.vendor="afsh4ck"

# Copy Go tools from gotools stage
COPY --from=gotools /opt/go/bin/ /usr/local/bin/

# Copy Python packages from pythondeps stage
COPY --from=pythondeps /usr/local/lib/python3.11/dist-packages/ /usr/local/lib/python3.11/dist-packages/
COPY --from=pythondeps /usr/local/bin/ /usr/local/bin/

# Create application directories
RUN mkdir -p /app/reports /app/config /app/plugins

# Copy application code
WORKDIR /app
COPY . .

# Ensure entrypoint is executable
RUN chmod +x main.py 2>/dev/null || true

EXPOSE 8080

ENTRYPOINT ["python3", "main.py"]
