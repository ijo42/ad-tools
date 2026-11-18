#!/bin/sh
# pcapstream.sh — стрим трафика с vulnbox на ноутбук по PCAP-over-IP (порт 57012).
# На ноутбуке должен быть запущен ingest.py (web.py --with-ingest).
#
# Запуск: sudo ./pcapstream.sh <IP_ноутбука> [интерфейс]
# Опционально: POIP_TOKEN=<секрет> — должен совпадать с ingest.poip_token
# в config.yaml ноутбука (иначе соединение закрывается сервером).
LAPTOP="${1:?usage: pcapstream.sh <IP_ноутбука> [iface]}"
IFACE="${2:-any}"

while true; do
  if [ -n "$POIP_TOKEN" ]; then
    # сервер ждёт токен первыми байтами потока, потом pcap-стрим
    { printf '%s' "$POIP_TOKEN"; tcpdump -i "$IFACE" -U -s 0 -w - \
        'not port 22 and not port 9100'; } | nc "$LAPTOP" 57012
  else
    tcpdump -i "$IFACE" -U -s 0 -w - \
      'not port 22 and not port 9100' \
      | nc "$LAPTOP" 57012
  fi
  echo "[pcapstream] соединение оборвалось, переподключение через 2с" >&2
  sleep 2
done
