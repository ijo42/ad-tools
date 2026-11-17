# Образ capture-стороны vulnbox: python (capture.py) + tcpdump + nc (pcapstream).
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY capture.py /app/capture.py
COPY pcapstream.sh /app/pcapstream.sh
RUN chmod +x /app/pcapstream.sh

# команда задаётся в docker-compose (capture или pcapstream)
