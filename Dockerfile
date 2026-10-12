FROM python:3.11-slim

# ======== системные зависимости ========
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ======== nuclei (DAST) ========
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) NUCLEI_ARCH="linux_amd64" ;; \
      arm64) NUCLEI_ARCH="linux_arm64" ;; \
      *) NUCLEI_ARCH="linux_amd64" ;; \
    esac && \
    NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d 'v') && \
    echo "Installing nuclei v${NUCLEI_VER} for ${NUCLEI_ARCH}" && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    nuclei -version
    
# ======== Python-зависимости ========
COPY requirements.txt .
RUN pip install --no-cache-dir uv
RUN uv pip install --system -r requirements.txt
RUN uv pip install --system semgrep

# ======== агент ========
COPY agent.py .
COPY tools/ ./tools/
COPY rules/ ./rules/
COPY prompts/ ./prompts/
COPY schemas/ ./schemas/

# ======== папка с отчетами ========
RUN mkdir -p /app/reports

# ======== настройка окружения ========
ENV PYTHONUNBUFFERED=1

# ======== запуск ========
CMD ["python", "-u", "agent.py", \
     "--url", "http://juice-shop:3000", \
     "--source", "/app/juice-shop", \
     "--rules", "/app/rules/rules_semgrep.yaml"]