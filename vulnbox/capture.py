#!/usr/bin/env python3
"""capture.py — пассивная запись трафика vulnbox с именованием по раундам.

Надёжная замена shell-«ренеймеру»: ОДИН процесс читает поток tcpdump
(`tcpdump -w -`) и сам режет его на файлы, именуя на момент записи:

    r{РАУНД}_p{PART}_{ЧЧММСС}.pcap

- РАУНД — номер раунда от начала зачёта GAME_START (unix epoch);
  до старта всё пишется как раунд 0;
- PART — номер окна внутри раунда (1..ROUND_LEN/WINDOW);
- ЧЧММСС — абсолютное время начала окна (из таймстемпов pcap-записей,
  поэтому не боится буферизации и скачков загрузки).

Почему это надёжнее shell-ренеймера:
- нет гонок «renamer vs tcpdump»: файл создаётся сразу с финальным именем,
  tcpdump не участвует в именовании вовсе;
- разделение потока по таймстемпам pcap-записей, а не по wall clock —
  окно «не плывёт» под нагрузкой;
- автоперезапуск tcpdump при обрыве; корректное закрытие по SIGTERM/SIGINT;
- отсутствие трафика в окне = файла нет (никаких пустых файлов).

Запуск: sudo python3 capture.py -i any -o /tmp/caps -s 1764180000 -r 60 -w 20
Файлы забираются ноутбуком (laptop/pull.sh, poll) или стримятся
в live-режиме (vulnbox/pcapstream.sh). Только пассивный просмотр (п. 8.9).
"""

import argparse
import os
import signal
import struct
import subprocess
import sys
import time

DEFAULT_FILTER = "not port 22 and not port 9100"
MAX_READ = 262144

# Magic'и pcap: байты в файле -> порядок байт полей.
# LE-машина пишет uint32 0xA1B2C3D4 как байты d4 c3 b2 a1.
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # usec, little-endian
    b"\xa1\xb2\xc3\xd4": ">",  # usec, big-endian
    b"\x4d\x3c\xb2\xa1": "<",  # nsec, little-endian
    b"\xa1\xb2\x3c\x4d": ">",  # nsec, big-endian
}


def file_key(ts, start, round_len, window):
    """(round, part, window_start) для записи с таймстемпом ts.

    Окна выровнены по абсолютному времени: window_start — время начала
    окна, в которое попала запись (именно оно идёт в имя файла).
    """
    if start <= 0 or ts < start:
        ws = (ts // window) * window
        return 0, 1, ws
    offset = ts - start
    win_idx = offset // window
    window_start = start + win_idx * window
    round_no = offset // round_len
    part = win_idx % (round_len // window) + 1
    return round_no, part, window_start


class Splitter:
    def __init__(self, outdir, start, round_len, window):
        self.outdir = outdir
        self.start = start
        self.round_len = round_len
        self.window = window
        self.gheader = None
        self.end = "<"
        self.out = None
        self.cur_key = None
        self.written = 0

    def open_for(self, ts):
        round_no, part, window_start = file_key(
            ts, self.start, self.round_len, self.window)
        key = (round_no, part, window_start)
        if self.out is not None and key == self.cur_key:
            return
        if self.out is not None:
            self.out.close()
            print(f"[capture] closed r{self.cur_key[0]:04d}_p{self.cur_key[1]}"
                  f" ({self.written} packets)", flush=True)
        hhmmss = time.strftime("%H%M%S", time.localtime(window_start))
        name = f"r{round_no:04d}_p{part}_{hhmmss}.pcap"
        self.out = open(f"{self.outdir}/{name}", "wb")
        self.out.write(self.gheader)
        self.cur_key = key
        self.written = 0
        print(f"[capture] -> {name}", flush=True)

    def write_record(self, ts_sec, record):
        self.open_for(ts_sec)
        self.out.write(record)
        self.written += 1

    def close(self):
        if self.out is not None:
            self.out.close()
            self.out = None


def run(iface, outdir, start, round_len, window, filt):
    os.makedirs(outdir, exist_ok=True)
    stop = False

    def on_sig(_sig, _frm):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)

    while not stop:
        proc = subprocess.Popen(
            ["tcpdump", "-i", iface, "-U", "-s", "0", "-w", "-", filt],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        print(f"[capture] tcpdump started on {iface}", flush=True)
        sp = Splitter(outdir, start, round_len, window)
        buf = b""
        try:
            while not stop:
                # os.read возвращает сколько есть (pipe + tcpdump -U шлёт
                # по пакетам); BufferedReader.read() ждал бы полные MAX_READ
                chunk = os.read(proc.stdout.fileno(), MAX_READ)
                if not chunk:
                    break  # tcpdump завершился
                buf += chunk
                # глобальный заголовок
                if sp.gheader is None:
                    if len(buf) < 24:
                        continue
                    magic = buf[:4]
                    if magic not in _MAGICS:
                        print("[capture] не pcap-поток (pcapng?), "
                              "пропускаю байт", flush=True)
                        buf = buf[1:]
                        continue
                    sp.end = _MAGICS[magic]
                    sp.gheader = buf[:24]
                    buf = buf[24:]
                # записи: заголовок 16 байт + incl_len данных
                while True:
                    if len(buf) < 16:
                        break
                    ts_sec, _frac, incl, _orig = struct.unpack(
                        sp.end + "IIII", buf[:16])
                    if incl == 0 or incl > 262144:
                        # рассинхронизация — сдвиг на байт
                        buf = buf[1:]
                        continue
                    if len(buf) < 16 + incl:
                        break
                    record = buf[:16 + incl]
                    buf = buf[16 + incl:]
                    sp.write_record(ts_sec, record)
        finally:
            sp.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if not stop:
            print("[capture] tcpdump оборвался, перезапуск через 2с", flush=True)
            time.sleep(2)
    print("[capture] stopped", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-i", "--iface", default="any")
    ap.add_argument("-o", "--outdir", default="/tmp/caps")
    ap.add_argument("-s", "--start", type=int, default=0,
                    help="unix epoch начала зачёта (0 — всё раунд 0)")
    ap.add_argument("-r", "--round-len", type=int, default=60,
                    help="длина раунда, сек (п. 2.1)")
    ap.add_argument("-w", "--window", type=int, default=20,
                    help="окно записи, сек")
    ap.add_argument("--filter", default=DEFAULT_FILTER)
    args = ap.parse_args()
    run(args.iface, args.outdir, args.start, args.round_len, args.window,
        args.filter)
    return 0


if __name__ == "__main__":
    sys.exit(main())
