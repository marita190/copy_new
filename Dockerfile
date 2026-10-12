# ======== учебный контур LFI/RFI ========
FROM python:3.11-slim AS file-inclusion

WORKDIR /lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY target/LFI_RFI_service.py target/LFI_RFI_remote.py target/fi_private_page.py ./
COPY target/fi_pages/ ./fi_pages/

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LAB_HOST=0.0.0.0
USER 10001:10001
EXPOSE 5101 5102
CMD ["python", "LFI_RFI_service.py"]

# ======== агент (образ по умолчанию) ========
FROM python:3.11-slim AS agent

# ======== системные зависимости ========
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ======== nuclei (DAST) ========
RUN curl -sSfL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/cmd/nuclei/nuclei_install.sh \
    | sh -s -- -b /usr/local/bin \
    || (curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d '"' -f4 | tr -d 'v')_linux_amd64.zip -o nuclei.zip \
        && unzip nuclei.zip -d /usr/local/bin \
        && rm nuclei.zip)

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
