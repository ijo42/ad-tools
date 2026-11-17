#!/bin/sh
# pcapstream.sh — стрим трафика с vulnbox на ноутбук по PCAP-over-IP (порт 57012).
# На ноутбуке должен быть запущен ingest.py.
#
# Запуск: sudo ./pcapstream.sh <IP_ноутбука> [интерфейс]
LAPTOP="${1:?usage: pcapstream.sh <IP_ноутбука> [iface]}"
IFACE="${2:-any}"

while true; do
  tcpdump -i "$IFACE" -U -s 0 -w - \
    'not port 22 and not port 9100' \
    | nc "$LAPTOP" 57012
  echo "[pcapstream] соединение оборвалось, переподключение через 2с" >&2
  sleep 2
done
