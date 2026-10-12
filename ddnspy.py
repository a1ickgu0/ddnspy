#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ddnspy — a small Cloudflare DDNS updater.

Reads a JSON config file, detects this host's public IPv4/IPv6 address
(external HTTP endpoints and/or local interface addresses) and keeps the
configured Cloudflare DNS records in sync.

Designed to run as a systemd service on Debian / Raspberry Pi OS, and
works equally well as a one-shot CLI for testing or cron.

Standard library only — no pip dependencies.  Requires Python >= 3.8.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, NoReturn, Optional, Tuple

__version__ = "1.0.0"

APP_NAME = "ddnspy"
CF_API_BASE = "https://api.cloudflare.com/client/v4"

# Used (in order) when the configured endpoint fails.  Each returns the
# caller's IP address as plain text and is reachable over IPv4 / IPv6.
IPV4_FALLBACK_ENDPOINTS = ("https://ipv4.icanhazip.com", "https://api.ipify.org")
IPV6_FALLBACK_ENDPOINTS = ("https://ipv6.icanhazip.com", "https://api6.ipify.org")

log = logging.getLogger(APP_NAME)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def dig(cfg: dict, path: str, default: Any = None) -> Any:
    """Fetch a nested value from a dict, e.g. dig(cfg, "wan.check_interval", 30)."""
    node: Any = cfg
    for key in path.split("."):
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return default if node is None else node


def die(msg: str, code: int = 1) -> NoReturn:
    print(f"{APP_NAME}: error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        die(f"config file not found: {path}")
    except json.JSONDecodeError as exc:
        die(f"config file is not valid JSON: {path}: {exc}")
    if not isinstance(cfg, dict):
        die("config root must be a JSON object")

    if not dig(cfg, "cloudflare.api_token"):
        die("cloudflare.api_token is required")
    records = cfg.get("records")
    if not isinstance(records, list) or not records:
        die("records must be a non-empty list")
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            die(f"records[{idx}] must be an object")
        for key in ("zone_name", "record_name", "record_type"):
            if not rec.get(key):
                die(f"records[{idx}].{key} is required")
        if str(rec["record_type"]).upper() not in ("A", "AAAA"):
            die(f"records[{idx}].record_type must be A or AAAA "
                f"(got {rec['record_type']!r})")
    return cfg


def setup_logging(cfg: dict, verbose: bool) -> None:
    level_name = str(dig(cfg, "app.log_level") or dig(cfg, "logging.level")
                     or "INFO").upper()
    if verbose or bool(dig(cfg, "app.verbose", False)) or level_name == "DEBUG":
        level = logging.DEBUG
    else:
        level = getattr(logging, level_name, logging.INFO)

    if str(dig(cfg, "logging.format", "timestamp")) == "timestamp":
        fmt = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    else:
        fmt = "%(levelname)-7s %(message)s"

    log.setLevel(level)
    log.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt))
    log.addHandler(handler)
    log.propagate = False

    log_path = dig(cfg, "app.log_path") or None
    if log_path:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(str(log_path))),
                        exist_ok=True)
            file_handler = logging.FileHandler(str(log_path))
            file_handler.setFormatter(logging.Formatter(fmt))
            log.addHandler(file_handler)
        except OSError as exc:
            log.warning("cannot open log file %s (%s); logging to stdout only",
                        log_path, exc)


# ---------------------------------------------------------------------------
# low-level HTTP / IP detection
# ---------------------------------------------------------------------------

def _family_of(version: int) -> int:
    return socket.AF_INET if version == 4 else socket.AF_INET6


def http_get_text(url: str, timeout: float, family: Optional[int] = None) -> str:
    """GET a small text body.

    When `family` is given, the connection is forced onto that address
    family so dual-stack endpoints (e.g. https://ip.sb) still report the
    right IP version.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme in {url!r}")
    host = parts.hostname
    if not host:
        raise ValueError(f"invalid URL {url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))

    infos = socket.getaddrinfo(host, port, family=family or 0,
                               type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"no usable address for {host}")

    raw = socket.create_connection(infos[0][4], timeout=timeout)
    if parts.scheme == "https":
        raw = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = raw  # pre-connected socket; http.client uses it as-is
    try:
        conn.request("GET", target,
                     headers={"User-Agent": f"{APP_NAME}/{__version__}",
                              "Accept": "text/plain"})
        resp = conn.getresponse()
        body = resp.read(2048).decode("utf-8", "replace")
        if resp.status != 200:
            raise OSError(f"HTTP {resp.status} from {url}")
        return body.strip()
    finally:
        conn.close()


def _parse_ip(text: str, version: int) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(addr) if addr.version == version else None


def detect_external_ip(version: int, cfg: dict,
                       endpoint_override: Optional[str] = None) -> Optional[str]:
    """Ask an external endpoint for this host's public address."""
    timeout = float(dig(cfg, "ip_detection.timeout_ms", 5000) or 5000) / 1000.0
    retries = max(1, int(dig(cfg, "ip_detection.retry_count", 3) or 3))
    delay = float(dig(cfg, "ip_detection.retry_delay_ms", 1000) or 1000) / 1000.0

    endpoints: List[str] = []
    for url in (endpoint_override,
                dig(cfg, "ip_detection.ipv4_endpoint" if version == 4
                    else "ip_detection.ipv6_endpoint")):
        if url and url not in endpoints:
            endpoints.append(str(url))
    for url in (IPV4_FALLBACK_ENDPOINTS if version == 4
                else IPV6_FALLBACK_ENDPOINTS):
        if url not in endpoints:
            endpoints.append(url)

    family = _family_of(version)
    last_error: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        for url in endpoints:
            try:
                ip = _parse_ip(http_get_text(url, timeout, family=family), version)
                if ip:
                    log.debug("external IPv%d %s via %s", version, ip, url)
                    return ip
                last_error = ValueError(f"{url} returned a non-IP body")
            except Exception as exc:  # best-effort probing of endpoints
                last_error = exc
                log.debug("IP endpoint %s failed: %s", url, exc)
        if attempt < retries:
            time.sleep(delay)
    log.warning("external IPv%d detection failed after %d attempt(s): %s",
                version, retries, last_error)
    return None


def default_route_addr(version: int) -> Optional[str]:
    """Source address the kernel would pick for the default route.

    UDP connect() only touches the routing table — no packet is sent.
    """
    target = ("192.0.2.1", 9) if version == 4 else ("2001:db8::1", 9)
    sock = socket.socket(_family_of(version), socket.SOCK_DGRAM)
    try:
        sock.settimeout(2.0)
        sock.connect(target)
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


# matches "inet 192.0.2.1/24 ..." (Linux `ip`) and "inet 192.0.2.1 netmask ..."
# (BSD/macOS `ifconfig`), likewise for inet6 with optional %scope suffix
_ADDR_TOKEN_RE = re.compile(
    r"\binet6?\s+([0-9A-Fa-f:.]+?)(?:/\d+)?(?:%[\w.]+)?(?=\s|$)")


def interface_addr(iface: str, version: int) -> Optional[str]:
    """Global (non link-local/loopback) address of `iface`, or None."""
    commands = (
        ["ip", f"-{version}", "-o", "addr", "show", "dev", iface],  # Linux
        ["ifconfig", iface],                                        # BSD/macOS
    )
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        lines = proc.stdout.splitlines()
        scoped = [ln for ln in lines if "scope global" in ln] or lines
        for line in scoped:
            match = _ADDR_TOKEN_RE.search(line)
            if not match:
                continue
            try:
                addr = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if addr.version != version or addr.is_link_local or addr.is_loopback:
                continue
            return str(addr)
    return None


# ---------------------------------------------------------------------------
# Cloudflare API client
# ---------------------------------------------------------------------------

class CloudflareError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _cf_errors(payload: dict) -> str:
    errors = payload.get("errors") or []
    if isinstance(errors, list) and errors:
        parts = []
        for err in errors:
            if isinstance(err, dict):
                parts.append(f"[{err.get('code')}] {err.get('message')}")
            else:
                parts.append(str(err))
        return "; ".join(parts)
    return "unknown Cloudflare API error"


def _effective_ttl(ttl: int, proxied: bool) -> int:
    """Cloudflare forces TTL to 1 ("auto") for proxied records."""
    return 1 if proxied else ttl


class Cloudflare:
    """Minimal Cloudflare API v4 client using a Bearer API token."""

    def __init__(self, token: str, timeout: float = 15.0):
        self._token = token
        self._timeout = timeout

    def _request(self, method: str, path: str,
                 params: Optional[Dict[str, str]] = None,
                 body: Optional[dict] = None, retries: int = 1) -> Any:
        url = CF_API_BASE + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "User-Agent": f"{APP_NAME}/{__version__}",
        }

        last: Optional[Exception] = None
        for attempt in range(1, max(1, retries) + 1):
            request = urllib.request.Request(url, data=data, method=method,
                                             headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8", "replace"))
                if not payload.get("success"):
                    raise CloudflareError(resp.status, _cf_errors(payload))
                return payload.get("result")
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict) and not payload.get("success", True):
                    raise CloudflareError(exc.code, _cf_errors(payload)) from None
                raise CloudflareError(exc.code,
                                      f"HTTP {exc.code}: {raw[:300]}") from None
            except (urllib.error.URLError, TimeoutError, OSError,
                    json.JSONDecodeError) as exc:
                last = exc
                if attempt < max(1, retries):
                    time.sleep(1.5 * attempt)
        raise CloudflareError(0, f"network error after {max(1, retries)} "
                                 f"attempt(s): {last}")

    # -- endpoints used by ddnspy -------------------------------------------

    def verify_token(self) -> str:
        result = self._request("GET", "/user/tokens/verify", retries=3)
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return str(result[0].get("status") or "unknown")
        return "unknown"

    def zone_id(self, zone_name: str) -> str:
        result = self._request("GET", "/zones",
                               params={"name": zone_name, "per_page": "5"},
                               retries=3)
        for zone in result or []:
            if zone.get("name") == zone_name:
                return str(zone["id"])
        raise CloudflareError(404, f"zone {zone_name!r} not found — check the "
                                   f"token permissions and the zone name")

    def find_record(self, zone_id: str, rtype: str, name: str) -> Optional[dict]:
        result = self._request("GET", f"/zones/{zone_id}/dns_records",
                               params={"type": rtype, "name": name,
                                       "per_page": "100"},
                               retries=3)
        records = result or []
        if len(records) > 1:
            log.warning("%s %s has %d records in Cloudflare; managing only the "
                        "first (%s) — clean up the others",
                        rtype, name, len(records), records[0].get("id"))
        return records[0] if records else None

    def create_record(self, zone_id: str, rtype: str, name: str, content: str,
                      ttl: int, proxied: bool) -> dict:
        body = {"type": rtype, "name": name, "content": content,
                "ttl": _effective_ttl(ttl, proxied), "proxied": proxied}
        return self._request("POST", f"/zones/{zone_id}/dns_records", body=body)

    def update_record(self, zone_id: str, record_id: str, rtype: str, name: str,
                      content: str, ttl: int, proxied: bool) -> dict:
        body = {"type": rtype, "name": name, "content": content,
                "ttl": _effective_ttl(ttl, proxied), "proxied": proxied}
        return self._request("PATCH", f"/zones/{zone_id}/dns_records/{record_id}",
                             body=body, retries=2)

    def delete_record(self, zone_id: str, record_id: str) -> Any:
        return self._request("DELETE",
                             f"/zones/{zone_id}/dns_records/{record_id}",
                             retries=2)


# ---------------------------------------------------------------------------
# DDNS engine
# ---------------------------------------------------------------------------

@dataclass
class RecordState:
    cfg: dict
    interval: float = 30.0
    zone_id: Optional[str] = None
    remote: Optional[dict] = None   # last known Cloudflare record
    next_check: float = 0.0

    @property
    def label(self) -> str:
        return f"{self.cfg.get('record_name', '?')}/{self.cfg.get('record_type', '?')}"


class Ddns:
    def __init__(self, cfg: dict, dry_run: bool = False):
        self.cfg = cfg
        self.dry_run = dry_run
        self.cf = Cloudflare(str(dig(cfg, "cloudflare.api_token")))
        self.parallel = bool(dig(cfg, "global_settings.parallel_updates", False))
        self.max_workers = max(1, int(dig(cfg, "global_settings.max_concurrent_updates", 5) or 5))
        self.ip_freshness = max(5.0, float(dig(cfg, "wan.check_interval", 30) or 30))

        default_interval = float(dig(cfg, "global_settings.default_check_interval", 30) or 30)
        self.states: List[RecordState] = []
        for rec in cfg["records"]:
            state = RecordState(cfg=rec)
            state.interval = max(5.0, float(rec.get("check_interval") or default_interval))
            self.states.append(state)

        self._ip_cache: Dict[Tuple[int, Optional[str]], Tuple[float, Optional[str]]] = {}
        self._ip_lock = threading.Lock()
        self._stop = threading.Event()

    # -- address detection ---------------------------------------------------

    def _iter_interfaces(self) -> List[dict]:
        interfaces = dig(self.cfg, "wan.interfaces") or []
        rows = [i for i in interfaces if isinstance(i, dict) and i.get("enabled", True)]
        rows.sort(key=lambda i: int(i.get("priority", 100) or 100))
        return rows

    def _detect_ip_uncached(self, version: int,
                            only_iface: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        for itf in self._iter_interfaces():
            if only_iface and itf.get("name") != only_iface:
                continue
            detect_key = "detect_ipv4" if version == 4 else "detect_ipv6"
            if not itf.get(detect_key, version == 4):
                continue
            if itf.get("use_external_detect", True):
                endpoint = itf.get("ipv4_endpoint") if version == 4 \
                    else itf.get("ipv6_endpoint")
                ip = detect_external_ip(version, self.cfg, endpoint)
                if ip:
                    return ip, f"{itf.get('name')}/external"
            if itf.get("use_local_read", False):
                name = str(itf.get("name") or "")
                ip = interface_addr(name, version) if name else None
                ip = ip or default_route_addr(version)
                if ip:
                    return ip, f"{itf.get('name')}/local"
        if not only_iface:
            fallback_iface = dig(self.cfg, "wan.default_interface")
            if fallback_iface:
                ip = interface_addr(str(fallback_iface), version)
                if ip:
                    return ip, f"{fallback_iface}/local"
            ip = default_route_addr(version)
            if ip:
                return ip, "default-route"
        return None, None

    def detect_ip(self, version: int, only_iface: Optional[str] = None) -> Optional[str]:
        key = (version, only_iface)
        with self._ip_lock:
            cached = self._ip_cache.get(key)
        if cached and time.time() - cached[0] < self.ip_freshness:
            return cached[1]

        ip, source = self._detect_ip_uncached(version, only_iface)
        previous = cached[1] if cached else None
        if ip is None:
            ip = previous  # transient failure — keep the last known address
            if ip:
                log.debug("IPv%d detection failed; keeping last known %s",
                          version, ip)
        if ip != previous:
            log.info("detected public IPv%d: %s (source: %s)",
                     version, ip, source or "cached")
        else:
            log.debug("IPv%d still %s", version, ip)
        with self._ip_lock:
            self._ip_cache[key] = (time.time(), ip)
        return ip

    # -- record synchronisation ----------------------------------------------

    def sync_record(self, state: RecordState) -> bool:
        rec = state.cfg
        rtype = str(rec["record_type"]).upper()
        version = 4 if rtype == "A" else 6

        only_iface: Optional[str] = None
        if str(rec.get("binding_mode", "auto")) == "interface":
            only_iface = rec.get("wan_interface") or None
            if not only_iface:
                log.warning("%s: binding_mode=interface but wan_interface is "
                            "empty; falling back to auto", state.label)

        ip = self.detect_ip(version, only_iface)
        if not ip:
            log.error("%s: no IPv%d address could be detected; skipping this "
                      "cycle", state.label, version)
            return False

        ttl = max(1, int(rec.get("ttl") or 300))
        proxied = bool(rec.get("proxied", False))
        eff_ttl = _effective_ttl(ttl, proxied)

        try:
            if not state.zone_id:
                state.zone_id = self.cf.zone_id(str(rec["zone_name"]))
                log.info("%s: zone %s -> %s", state.label, rec["zone_name"],
                         state.zone_id)

            if state.remote is None:
                state.remote = self.cf.find_record(state.zone_id, rtype,
                                                   str(rec["record_name"]))
                if state.remote is None:
                    if not rec.get("create_if_missing", True):
                        log.warning("%s: record missing in Cloudflare and "
                                    "create_if_missing is false", state.label)
                        return False
                    if self.dry_run:
                        log.info("[dry-run] %s: would create %s -> %s "
                                 "(ttl=%d, proxied=%s)", state.label,
                                 rec["record_name"], ip, eff_ttl, proxied)
                        return True
                    state.remote = self.cf.create_record(
                        state.zone_id, rtype, str(rec["record_name"]),
                        ip, ttl, proxied)
                    log.info("%s: created %s -> %s (ttl=%d, proxied=%s)",
                             state.label, rec["record_name"], ip, eff_ttl,
                             proxied)
                    return True

            old_ip = state.remote.get("content")
            old_proxied = bool(state.remote.get("proxied"))
            old_ttl = int(state.remote.get("ttl") or 1)
            force_refresh = not bool(rec.get("update_on_change", True))
            changed = (old_ip != ip
                       or old_proxied != proxied
                       or (not proxied and old_ttl != ttl))
            if not (changed or force_refresh):
                log.debug("%s: up to date (%s)", state.label, old_ip)
                return True

            if self.dry_run:
                log.info("[dry-run] %s: would update %s -> %s (ttl=%d, "
                         "proxied=%s%s)", state.label, old_ip, ip, eff_ttl,
                         proxied, ", forced" if force_refresh and not changed else "")
                return True

            state.remote = self.cf.update_record(
                state.zone_id, str(state.remote["id"]), rtype,
                str(rec["record_name"]), ip, ttl, proxied)
            log.info("%s: updated %s -> %s (ttl=%d, proxied=%s)",
                     state.label, old_ip, ip, eff_ttl, proxied)
            return True

        except CloudflareError as exc:
            log.error("%s: Cloudflare API error: %s", state.label, exc)
            if exc.status == 404:
                if state.remote is not None:
                    log.info("%s: record no longer exists remotely; will "
                             "recreate on the next pass", state.label)
                    state.remote = None
                state.zone_id = None
            elif exc.status in (401, 403):
                log.error("%s: token rejected — check the API token and its "
                          "permissions/scopes", state.label)
            return False

    # -- scheduling ------------------------------------------------------------

    def cycle(self) -> bool:
        now = time.time()
        due = [state for state in self.states if now >= state.next_check]
        if not due:
            return True

        ok = True
        if self.parallel and len(due) > 1:
            workers = min(self.max_workers, len(due))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self.sync_record, state): state
                           for state in due}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        if not future.result():
                            ok = False
                    except Exception:
                        ok = False
                        log.exception("unexpected error updating %s",
                                      futures[future].label)
        else:
            for state in due:
                try:
                    if not self.sync_record(state):
                        ok = False
                except Exception:
                    ok = False
                    log.exception("unexpected error updating %s", state.label)

        for state in due:
            state.next_check = time.time() + state.interval
        return ok

    def verify_token(self) -> None:
        log.info("Cloudflare token verified (%s)", self.cf.verify_token())

    def run_once(self) -> int:
        try:
            self.verify_token()
        except CloudflareError as exc:
            log.error("token verification failed: %s", exc)
            return 2
        ok = self.cycle()
        log.info("single pass complete")
        return 0 if ok else 2

    def _on_signal(self, signum: int, _frame: Any) -> None:
        log.debug("signal %d received", signum)
        self._stop.set()

    def run_forever(self) -> int:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._on_signal)
        try:
            self.verify_token()
        except CloudflareError as exc:
            log.error("token verification failed: %s", exc)
            return 2

        log.info("entering daemon mode (record check intervals: %s)",
                 ", ".join(f"{s.label}={s.interval:.0f}s" for s in self.states))
        while not self._stop.is_set():
            try:
                self.cycle()
            except Exception:
                log.exception("cycle failed")
            wake = min((state.next_check for state in self.states),
                       default=time.time() + 5.0)
            deadline = time.time() + max(1.0, min(5.0, wake - time.time()))
            while not self._stop.wait(0.5):
                if time.time() >= deadline:
                    break

        log.info("shutting down")
        self._handle_delete_on_exit()
        return 0

    def _handle_delete_on_exit(self) -> None:
        for state in self.states:
            if not (state.cfg.get("delete_on_exit") and state.remote
                    and state.zone_id):
                continue
            if self.dry_run:
                log.info("[dry-run] %s: would delete record on exit",
                         state.label)
                continue
            try:
                self.cf.delete_record(state.zone_id, str(state.remote["id"]))
                state.remote = None
                log.info("%s: deleted (delete_on_exit)", state.label)
            except CloudflareError as exc:
                log.error("%s: delete_on_exit failed: %s", state.label, exc)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Config-file driven Cloudflare DDNS updater.")
    parser.add_argument("-c", "--config", metavar="PATH",
                        help="config file path (default: ./config.json, "
                             "then /etc/ddnspy/config.json)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true",
                      help="run a single sync pass and exit "
                           "(overrides the config)")
    mode.add_argument("--daemon", action="store_true",
                      help="keep running until stopped "
                           "(overrides the config)")
    parser.add_argument("--dry-run", action="store_true",
                        help="detect and compare, but do not change Cloudflare")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="debug logging")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {__version__}")
    return parser


def find_config_path(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    for path in ("./config.json", "/etc/ddnspy/config.json"):
        if os.path.isfile(path):
            return path
    die("no config file found; use --config PATH")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = find_config_path(args.config)
    cfg = load_config(config_path)

    once_mode = args.once or (
        not args.daemon and (
            bool(dig(cfg, "app.once", False))
            or not bool(dig(cfg, "app.daemon", True))
        )
    )

    setup_logging(cfg, args.verbose)
    log.info("%s %s starting (config=%s, mode=%s%s)", APP_NAME, __version__,
             config_path, "once" if once_mode else "daemon",
             ", dry-run" if args.dry_run else "")

    engine = Ddns(cfg, dry_run=args.dry_run)
    try:
        return engine.run_once() if once_mode else engine.run_forever()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
