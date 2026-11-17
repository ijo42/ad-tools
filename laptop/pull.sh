#!/bin/sh
# pull.sh — poll-режим: ноутбук САМ забирает pcap с vulnbox по SSH.
#
# Когда нужен: vulnbox не может сам достучаться до ноутбука (нет маршрута /
# firewall на ноутбуке), т.е. PCAP-over-IP и HTTP-загрузка с vulnbox недоступны.
# SSH в обратную сторону (ноутбук -> vulnbox) доступен всегда — вы по нему
# заходите на vulnbox (п. 3.1 регламента), поэтому poll идёт именно так.
#
# На vulnbox должен быть запущен capture.sh (ротированные pcap в /tmp/caps,
# 1 файл = 1 раунд). Файл отдаётся после того, как он «устоялся»
# (не менялся последнюю минуту) — так мы не грузим недописанный pcap.
#
# Запуск на ноутбуке (параллельно с web.py):
#   ./pull.sh root@10.10.1.42 http://127.0.0.1:57013/pcap
#   ./pull.sh <user>@<vulnbox> <ingest-url> [интервал_сек]
#
# Зависимости на ноутбуке: rsync (есть почти везде), ssh-ключи настроены
# заранее (проверьте до старта!).
VULNBOX="${1:?usage: pull.sh <user>@<vulnbox> <ingest-url> [interval]}"
INGEST="${2:-http://127.0.0.1:57013/pcap}"
INTERVAL="${3:-10}"

STATE_DIR="${AD_PULL_DIR:-$HOME/.ad-pull}"
PULLED="$STATE_DIR/pulled"
STATE="$STATE_DIR/pulled.list"
mkdir -p "$PULLED"
touch "$STATE"
echo "[pull] vulnbox=$VULNBOX -> $INGEST каждые ${INTERVAL}s (state: $STATE)"

while true; do
  # 1. забираем новые pcap
  if echo "$VULNBOX" | grep -q ':'; then
    rsync -az --include='*.pcap' --exclude='*' \
      "$VULNBOX:/tmp/caps/" "$PULLED/" 2>/dev/null
  else
    # локальный путь (для тестов): ./pull.sh /tmp/caps ...
    rsync -az --include='*.pcap' --exclude='*' \
      "$VULNBOX/" "$PULLED/" 2>/dev/null
  fi

  # 2. отдаём в ingest файлы, которые «устоялись» (>60с с момента записи)
  #    и ещё не отправлялись
  for f in "$PULLED"/*.pcap; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    grep -Fxq "$base" "$STATE" && continue
    # файл считается завершённым, если изменён более минуты назад
    if [ "$(find "$f" -mmin +1 2>/dev/null | wc -l)" -eq 1 ]; then
      if curl -sf --max-time 30 --data-binary @"$f" "$INGEST" >/dev/null; then
        echo "$base" >> "$STATE"
        echo "[pull] ok: $base"
      else
        echo "[pull] ingest недоступен, повторю позже: $base" >&2
        break
      fi
    fi
  done

  sleep "$INTERVAL"
done
