#!/bin/bash
# capture.sh — FALLBACK-вариант записи (если на vulnbox нет python3).
#
# Основной путь — vulnbox/capture.py: один процесс режет поток tcpdump по
# окнам и сразу именует файлы r{раунд}_p{part}_{ЧЧММСС}.pcap без гонок и
# без внешнего переименователя. Этот скрипт оставлен как простой fallback:
# tcpdump с окном 20с и служебными именами cap_YYYYMMDD_HHMMSS.pcap
# (round/part в этом режиме не вычисляются).
#
# Запуск: sudo ./capture.sh [iface] [outdir] [window]
# Файлы забираются ноутбуком в poll-режиме (laptop/pull.sh). Только
# пассивный просмотр (п. 8.9), фильтр исключает SSH и node-exporter (п. 8.12).

IFACE="${1:-any}"
OUTDIR="${2:-/tmp/caps}"
WINDOW="${3:-20}"
mkdir -p "$OUTDIR"
# tcpdump дропает привилегии до пользователя "tcpdump" — каталог должен
# быть доступен ему на запись для ротаций
chmod 1777 "$OUTDIR" 2>/dev/null || true

exec tcpdump -i "$IFACE" -U -s 0 \
  -G "$WINDOW" -w "$OUTDIR/cap_%Y%m%d_%H%M%S.pcap" \
  'not port 22 and not port 9100'
