FROM alpine:latest

RUN apk add --no-cache \
    python3 \
    py3-pip \
    iproute2 \
    iptables \
    tcpdump \
    curl \
    bash \
    libnetfilter_queue-dev \
    gcc \
    musl-dev \
    linux-headers \
    python3-dev

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

WORKDIR /app

CMD ["sleep", "infinity"]