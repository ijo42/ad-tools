"""Replay captured payloads against all teams (fast-track counter-attack)."""

import socket
import threading

from .flags import extract_flags
from .template import generalize, render


def load_teams(path):
    import yaml  # provided via `uv run --with pyyaml`

    with open(path) as fh:
        data = yaml.safe_load(fh)
    targets = []
    for team in data.get("teams", []):
        if team.get("disabled"):
            continue
        ports = []
        if "port" in team:
            ports.append(team["port"])
        for _svc, port in (team.get("services") or {}).items():
            ports.append(port)
        if not ports:
            ports.append(80)
        targets.append(
            {
                "name": team["name"],
                "host": team["host"],
                "ports": ports,
                "npc": bool(team.get("npc")),
            }
        )
    return targets


def split_npc(targets):
    """(npc_targets, team_targets) — NPC цели исключаются из обычного replay."""
    npc = [t for t in targets if t.get("npc")]
    teams = [t for t in targets if not t.get("npc")]
    return npc, teams


def send_payload(host, port, payload, timeout=5.0):
    """Send raw payload, read whatever comes back until timeout/EOF."""
    out = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                out += chunk
                if len(out) > 1048576:
                    break
    except OSError as exc:
        return out, str(exc)
    return out, None


def replay(payload, targets, mode="verbatim", flag_pattern=None, timeout=5.0,
           log_fn=print):
    """Replay to every target. mode: verbatim | template.

    In template mode the payload is generalized once (flag/uuid/token -> {FLAG}
    etc.) and rendered per target with the previous values removed (the exploit
    reads a fresh flag on each target, so placeholders are mostly stripped to
    their literal braces unless caller supplies overrides).
    Returns list of {target, port, response_len, flags, error}.
    """
    if mode == "template":
        template, params = generalize(payload)
        log_fn(
            f"[template] placeholders: {list(params)} — "
            f"переопределите overrides при необходимости"
        )
    else:
        template = payload
    results = []
    lock = threading.Lock()

    def worker(target, port):
        rendered = render(template, {}) if mode == "template" else payload
        resp, error = send_payload(target["host"], port, rendered, timeout)
        flags = extract_flags(resp, flag_pattern)
        with lock:
            results.append(
                {
                    "target": target["name"],
                    "host": target["host"],
                    "port": port,
                    "response_len": len(resp),
                    "flags": flags,
                    "error": error,
                }
            )
            mark = "!!" if error else "->"
            log_fn(
                f"  {mark} {target['name']}:{port} resp={len(resp)}B "
                f"flags={len(flags)}{' ' + str(error) if error else ''}"
            )

    threads = []
    for target in targets:
        for port in target["ports"]:
            th = threading.Thread(target=worker, args=(target, port))
            th.start()
            threads.append(th)
    for th in threads:
        th.join()
    return results


def harvest_flags(results, flag_pattern=None):
    all_flags = []
    for r in results:
        for flag in r["flags"]:
            if flag not in all_flags:
                all_flags.append(flag)
    return all_flags
