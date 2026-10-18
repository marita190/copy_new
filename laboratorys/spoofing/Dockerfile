FROM alpine:latest

# cистемные зависимости
RUN apk add --no-cache \
    python3 \
    py3-pip \
    iproute2 \
    iptables \
    tcpdump \
    curl \
    bash

# Python-зависимости
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

WORKDIR /app

CMD ["sleep", "infinity"]