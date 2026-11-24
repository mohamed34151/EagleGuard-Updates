"""EagleGuard threat-intelligence database and updater.

Downloads public, community-curated threat data from abuse.ch and stores it in
a local SQLite database (data/threat_intel.db):

    MalwareBazaar  malware file hashes + family name, file type, imphash, TLSH
    ThreatFox      indicators of compromise: hashes, IPs, domains, URLs
    Feodo Tracker  botnet command-and-control server IPs
    URLhaus        malware distribution URLs and their hosts

Design notes
    * Updates are atomic per source: a failed download never empties the data
      already stored, and each source reports its own status.
    * Lookups go through SQLite indexes, so a million hashes do not have to be
      loaded into memory (a Python dict of that size costs hundreds of MB).
    * abuse.ch may require a free Auth-Key for some downloads. Pass ``auth_key``
      (or set ABUSE_CH_AUTH_KEY); without it, sources that refuse are reported
      as AUTH_REQUIRED rather than failing silently.
    * The EICAR test file hash is always present so detection can be verified
      safely (EICAR is a harmless industry-standard test string).
"""
from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
from .paths import DATA_DIR
DEFAULT_DB = DATA_DIR / "threat_intel.db"
USER_AGENT = "EagleGuard-ThreatIntel/1.0"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# abuse.ch v2 exports (since late 2026 the old keyless links answer HTTP 410 Gone):
# the free Auth-Key from auth.abuse.ch goes INSIDE the URL path ({key}).
SOURCES = {
    "malwarebazaar_recent": {
        "title": "MalwareBazaar (آخر 48 ساعة)",
        "url": "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        "keyed": True,
    },
    "malwarebazaar_full": {
        "title": "MalwareBazaar (القاعدة الكاملة)",
        "url": "https://bazaar.abuse.ch/export/csv/full/",
        # No confirmed v2 link for the full dump yet; the recent feed accumulates instead.
        "unavailable": "رابط القاعدة الكاملة الجديد غير مؤكد بعد — البرنامج يجمع آخر 48 ساعة باستمرار بدلًا منها",
    },
    "threatfox": {
        "title": "ThreatFox (مؤشرات الاختراق)",
        "url": "https://threatfox-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        "keyed": True,
    },
    "feodo": {
        "title": "Feodo Tracker (خوادم تحكم)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    },
    "urlhaus": {
        "title": "URLhaus (روابط خبيثة)",
        "url": "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        "keyed": True,
    },
    "sslbl": {
        "title": "SSLBL (خوادم تحكم الفيروسات)",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    },
    "openphish": {
        "title": "OpenPhish (مواقع تصيّد نشطة)",
        "url": "https://openphish.com/feed.txt",
    },
    "eagleguard_cloud": {  # handled by cloud_updates.py, listed here for titles in reports
        "title": "سيرفر تحديثات EagleGuard (موقّع)",
        "url": "https://raw.githubusercontent.com/mohamed34151/EagleGuard-Updates/dist/manifest.json",
    },
    "upx_tool": {
        "title": "أداة UPX لفك التغليف",
        "url": "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-win64.zip",
    },
    "yara_forge_core": {
        "title": "YARA-Forge (قواعد الأنماط)",
        "url": "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
    },
}
DEFAULT_SOURCES = ("malwarebazaar_recent", "threatfox", "feodo", "urlhaus", "sslbl", "openphish",
                   "yara_forge_core", "upx_tool")
# Feeds that only publish a recent window (e.g. last 48 h) are merged so the
# database keeps growing with every update; "currently online" lists replace.
ACCUMULATING_SOURCES = {"malwarebazaar_recent", "malwarebazaar_full", "threatfox"}
NETWORK_IOC_MAX_AGE_DAYS = 90

SCHEMA = """
CREATE TABLE IF NOT EXISTS hashes (
    sha256 TEXT PRIMARY KEY, family TEXT, file_type TEXT, source TEXT,
    first_seen TEXT, imphash TEXT, tlsh TEXT, md5 TEXT, sha1 TEXT);
CREATE TABLE IF NOT EXISTS ips (
    ip TEXT NOT NULL, port INTEGER, family TEXT, source TEXT, first_seen TEXT,
    PRIMARY KEY (ip, port, source));
CREATE TABLE IF NOT EXISTS hosts (
    host TEXT NOT NULL, family TEXT, source TEXT, first_seen TEXT,
    PRIMARY KEY (host, source));
CREATE TABLE IF NOT EXISTS urls (
    url TEXT PRIMARY KEY, host TEXT, family TEXT, source TEXT, first_seen TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS idx_hashes_imphash ON hashes(imphash);
CREATE INDEX IF NOT EXISTS idx_ips_ip ON ips(ip);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return None if text in {"", "n/a", "None", "null"} else text


def _is_sha256(value: str | None) -> bool:
    return bool(value) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def _host_of(url: str) -> str | None:
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


class ThreatIntelDB:
    """Thread-safe SQLite store; ``get(sha256)`` matches the dict API the Malware Engine uses."""

    def __init__(self, path: Path | str = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._ensure_eicar()

    # ------------------------------------------------------------- lookups --
    def get(self, sha256: str, default=None):
        if not sha256:
            return default
        with self._lock:
            row = self._conn.execute(
                "SELECT family, source, file_type FROM hashes WHERE sha256 = ?", (sha256.lower(),)
            ).fetchone()
        if row is None:
            return default
        family, source, file_type = row
        return {"threat_name": family or "Known.Malware", "signature_id": f"{source}:{sha256[:12]}",
                "source": source, "file_type": file_type}

    def __contains__(self, sha256: str) -> bool:
        return self.get(sha256) is not None

    def __len__(self) -> int:
        return self.counts()["hashes"]

    def lookup_ip(self, ip: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ip, port, family, source FROM ips WHERE ip = ?", (ip,)).fetchall()
        return [{"ip": r[0], "port": r[1], "family": r[2], "source": r[3]} for r in rows]

    def known_ips(self) -> set[str]:
        with self._lock:
            return {r[0] for r in self._conn.execute("SELECT DISTINCT ip FROM ips")}

    def lookup_host(self, host: str) -> list[dict[str, Any]]:
        host = (host or "").lower().rstrip(".")
        with self._lock:
            rows = self._conn.execute(
                "SELECT host, family, source FROM hosts WHERE host = ?", (host,)).fetchall()
        return [{"host": r[0], "family": r[1], "source": r[2]} for r in rows]

    def families_for_imphash(self, imphash: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT family FROM hashes WHERE imphash = ? AND family IS NOT NULL LIMIT 10",
                (imphash.lower(),)).fetchall()
        return [r[0] for r in rows]

    def counts(self) -> dict[str, int]:
        with self._lock:
            return {table: self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("hashes", "ips", "hosts", "urls")}

    def meta(self) -> dict[str, Any]:
        with self._lock:
            rows = dict(self._conn.execute("SELECT key, value FROM meta").fetchall())
        try:
            sources = json.loads(rows.get("sources", "{}"))
        except ValueError:
            sources = {}
        return {"last_update_utc": rows.get("last_update_utc"), "sources": sources}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------- writing --
    def _ensure_eicar(self) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO hashes (sha256, family, file_type, source, first_seen) VALUES (?,?,?,?,?)",
                (EICAR_SHA256, "EICAR-Test-File (not a virus)", "txt", "builtin", None))

    def replace_source(self, source: str, *, hashes: Iterable[tuple] = (), ips: Iterable[tuple] = (),
                       hosts: Iterable[tuple] = (), urls: Iterable[tuple] = (), keep_existing: bool = False) -> dict[str, int]:
        """Atomically swap one source's rows (or merge them with keep_existing)."""
        added = {"hashes": 0, "ips": 0, "hosts": 0, "urls": 0}
        with self._lock, self._conn:
            if not keep_existing:
                for table in added:
                    self._conn.execute(f"DELETE FROM {table} WHERE source = ?", (source,))
            for row in hashes:
                self._conn.execute(
                    "INSERT OR REPLACE INTO hashes (sha256, family, file_type, source, first_seen, imphash, tlsh, md5, sha1)"
                    " VALUES (?,?,?,?,?,?,?,?,?)", row)
                added["hashes"] += 1
            for row in ips:
                self._conn.execute("INSERT OR REPLACE INTO ips (ip, port, family, source, first_seen) VALUES (?,?,?,?,?)", row)
                added["ips"] += 1
            for row in hosts:
                self._conn.execute("INSERT OR REPLACE INTO hosts (host, family, source, first_seen) VALUES (?,?,?,?)", row)
                added["hosts"] += 1
            for row in urls:
                self._conn.execute("INSERT OR REPLACE INTO urls (url, host, family, source, first_seen) VALUES (?,?,?,?,?)", row)
                added["urls"] += 1
        self._ensure_eicar()
        return added

    def prune_network_iocs(self, source: str, max_age_days: int) -> int:
        """Drop IP/host/URL indicators older than max_age_days (infrastructure changes hands)."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime("%Y-%m-%d")
        removed = 0
        with self._lock, self._conn:
            for table in ("ips", "hosts", "urls"):
                cur = self._conn.execute(
                    f"DELETE FROM {table} WHERE source = ? AND first_seen IS NOT NULL AND first_seen < ?",
                    (source, cutoff))
                removed += cur.rowcount
        return removed

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'history'").fetchone()
        try:
            return json.loads(row[0]) if row else []
        except ValueError:
            return []

    def record_update(self, results: dict[str, Any]) -> None:
        previous = self.meta()["sources"]
        previous.update(results)
        history = self.history()[-199:]
        history.append({"at_utc": _utc_now(), **self.counts(),
                        "ok": sum(1 for r in results.values() if r.get("status") == "UPDATED")})
        with self._lock, self._conn:
            self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('history', ?)", (json.dumps(history),))
            self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_update_utc', ?)", (_utc_now(),))
            self._conn.execute("INSERT OR REPLACE INTO meta VALUES ('sources', ?)",
                               (json.dumps(previous, ensure_ascii=False),))


# ------------------------------------------------------------------ parsers --

def _csv_rows(text: str) -> Iterator[list[str]]:
    lines = (line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    yield from csv.reader(lines, skipinitialspace=True)


def parse_malwarebazaar_csv(text: str, source: str) -> Iterator[tuple]:
    """Columns: first_seen, sha256, md5, sha1, reporter, file_name, file_type, mime,
    signature, clamav, vtpercent, imphash, ssdeep, tlsh."""
    for row in _csv_rows(text):
        if len(row) < 9 or not _is_sha256(row[1].strip()):
            continue
        get = lambda i: _clean(row[i]) if len(row) > i else None  # noqa: E731
        family = get(8) or get(9)
        yield (row[1].strip().lower(), family, get(6), source, get(0),
               (get(11) or "").lower() or None, get(13), get(2), get(3))


def parse_threatfox_json(text: str, source: str = "threatfox") -> dict[str, list[tuple]]:
    data = json.loads(text)
    entries: list[dict] = []
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            entries = data["data"]
        else:
            for value in data.values():
                if isinstance(value, list):
                    entries.extend(v for v in value if isinstance(v, dict))
    elif isinstance(data, list):
        entries = [v for v in data if isinstance(v, dict)]
    return _threatfox_entries(entries, source)


THREATFOX_CSV_COLUMNS = ["first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type", "fk_malware",
                         "malware_alias", "malware_printable", "last_seen_utc", "confidence_level",
                         "reference", "tags", "anonymous", "reporter"]


def parse_threatfox_csv(text: str, source: str = "threatfox") -> dict[str, list[tuple]]:
    """ThreatFox CSV export; column names come from the commented header when present."""
    columns = THREATFOX_CSV_COLUMNS
    for line in text.splitlines()[:30]:
        stripped = line.lstrip("# ").strip()
        if line.lstrip().startswith("#") and "ioc_value" in stripped:
            columns = [c.strip().strip('"') for c in next(csv.reader([stripped], skipinitialspace=True))]
            break
    entries = [dict(zip(columns, (v.strip() for v in row))) for row in _csv_rows(text) if len(row) >= 4]
    return _threatfox_entries(entries, source)


def parse_threatfox(text: str, source: str = "threatfox") -> dict[str, list[tuple]]:
    return parse_threatfox_json(text, source) if text.lstrip()[:1] in "{[" else parse_threatfox_csv(text, source)


def _threatfox_entries(entries: list[dict], source: str) -> dict[str, list[tuple]]:
    out: dict[str, list[tuple]] = {"hashes": [], "ips": [], "hosts": [], "urls": []}
    for entry in entries:
        value = _clean(entry.get("ioc_value") or entry.get("ioc"))
        kind = str(entry.get("ioc_type", "")).lower()
        family = _clean(entry.get("malware_printable") or entry.get("malware"))
        seen = _clean(entry.get("first_seen_utc") or entry.get("first_seen"))
        if not value:
            continue
        if kind == "sha256_hash" and _is_sha256(value):
            out["hashes"].append((value.lower(), family, None, source, seen, None, None, None, None))
        elif kind == "ip:port":
            ip, _, port = value.rpartition(":")
            if ip:
                out["ips"].append((ip.strip("[]"), int(port) if port.isdigit() else None, family, source, seen))
        elif kind == "domain":
            out["hosts"].append((value.lower().rstrip("."), family, source, seen))
        elif kind == "url":
            host = _host_of(value)
            out["urls"].append((value, host, family, source, seen))
            if host:
                out["hosts"].append((host, family, source, seen))
    return out


def parse_feodo_json(text: str, source: str = "feodo") -> list[tuple]:
    data = json.loads(text)
    rows = []
    for entry in data if isinstance(data, list) else []:
        ip = _clean(entry.get("ip_address"))
        if ip:
            port = entry.get("port")
            rows.append((ip, int(port) if str(port).isdigit() else None, _clean(entry.get("malware")),
                         source, _clean(entry.get("first_seen"))))
    return rows


def parse_urlhaus_csv(text: str, source: str = "urlhaus") -> dict[str, list[tuple]]:
    """Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter."""
    urls, hosts = [], {}
    for row in _csv_rows(text):
        if len(row) < 3 or "://" not in row[2]:
            continue
        url = row[2].strip()
        host = _host_of(url)
        family = _clean(row[6]) if len(row) > 6 else None
        seen = _clean(row[1])
        urls.append((url, host, family, source, seen))
        status = row[3].strip().lower() if len(row) > 3 else "online"
        if host and status in ("online", ""):  # dead links do not get their site blocked
            hosts[host] = (host, family, source, seen)
    return {"urls": urls, "hosts": list(hosts.values())}


def parse_sslbl_csv(text: str, source: str = "sslbl") -> list[tuple]:
    """Columns: Firstseen, DstIP, DstPort (botnet C&C servers seen with malicious TLS)."""
    out = []
    for row in _csv_rows(text):
        if len(row) >= 2 and row[1].strip().count(".") == 3:
            port = row[2].strip() if len(row) > 2 else ""
            out.append((row[1].strip(), int(port) if port.isdigit() else None, "Botnet C2 (SSLBL)", source,
                        _clean(row[0])))
    return out


def parse_url_list(text: str, source: str, family: str = "Phishing") -> dict[str, list[tuple]]:
    """One URL per line (OpenPhish). Every listed site is active phishing right now."""
    seen = _utc_now()
    urls, hosts = [], {}
    for line in text.splitlines():
        url = line.strip()
        if not url or url.startswith("#") or "://" not in url:
            continue
        host = _host_of(url)
        urls.append((url, host, family, source, seen))
        if host:
            hosts[host] = (host, family, source, seen)
    return {"urls": urls, "hosts": list(hosts.values())}


# --------------------------------------------------------------- download --

class DownloadError(Exception):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status


def _redact(text: str, key: str | None) -> str:
    """Hide the Auth-Key (plain or URL-encoded) from anything shown or logged."""
    if not key:
        return text
    for form in {key, urllib.parse.quote(key, safe="")}:
        text = text.replace(form, "***")
    return text


def download(url: str, *, auth_key: str | None = None, timeout: float = 120) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if auth_key:
        headers["Auth-Key"] = auth_key
    request = urllib.request.Request(url, headers=headers)
    try:
        from .net import urlopen
        with urlopen(request, timeout=timeout) as response:
            data = response.read()
    except urllib.error.HTTPError as exc:
        # 401 = missing/unknown key; 403 = key recognised but not allowed (account not
        # activated, terms not accepted, or limited for fair use).
        status = ("AUTH_REQUIRED" if exc.code == 401 else "AUTH_FORBIDDEN" if exc.code == 403 else
                  "RATE_LIMITED" if exc.code == 429 else "GONE" if exc.code == 410 else "HTTP_ERROR")
        raise DownloadError(status, f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        if "CERTIFICATE_VERIFY_FAILED" in str(reason):
            from .net import backend
            raise DownloadError("TLS_ERROR", f"certificate check failed ({backend()}): {reason}") from exc
        raise DownloadError("NETWORK_ERROR", f"{type(exc).__name__}: {exc}") from exc
    if data[:2] == b"PK":  # zipped export (the full MalwareBazaar dump)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            name = max(archive.namelist(), key=lambda n: archive.getinfo(n).file_size)
            data = archive.read(name)
    return data


# abuse.ch fair use: rate-limited accounts can be blocked for up to 72 hours. Each
# export is fetched at most this often, and after a 429 the source rests for a day.
MIN_INTERVAL = {"malwarebazaar_full": timedelta(days=7)}
DEFAULT_MIN_INTERVAL = timedelta(minutes=60)
RATE_LIMIT_BACKOFF = timedelta(hours=24)
SKIP_STATUSES = {"SKIPPED_RECENT", "WAITING_RATE_LIMIT"}


def _polite_skip(key: str, previous: dict | None, now: datetime) -> dict | None:
    if "abuse.ch" not in SOURCES[key]["url"] or not isinstance(previous, dict):
        return None
    try:
        last = datetime.fromisoformat(previous.get("at_utc"))
    except (TypeError, ValueError):
        return None
    status = previous.get("status")
    if status == "RATE_LIMITED" and now - last < RATE_LIMIT_BACKOFF:
        return {"status": "WAITING_RATE_LIMIT", "detail": f"rate-limited at {previous.get('at_utc')}; retry after 24h"}
    if status in ("UPDATED", "EMPTY") and now - last < MIN_INTERVAL.get(key, DEFAULT_MIN_INTERVAL):
        return {"status": "SKIPPED_RECENT", "detail": f"updated at {previous.get('at_utc')}"}
    return None


def update_all(db: ThreatIntelDB | None = None, *, sources: Iterable[str] = DEFAULT_SOURCES,
               auth_key: str | None = None, progress: Callable[[str, str], None] | None = None,
               fetch: Callable[[str], bytes] | None = None) -> dict[str, Any]:
    """Update every requested source; returns a per-source status report."""
    own_db = db is None
    db = db or ThreatIntelDB()
    auth_key = auth_key or os.environ.get("ABUSE_CH_AUTH_KEY") or None
    real_download = fetch is None
    fetch = fetch or (lambda url: download(url))
    results: dict[str, Any] = {}
    skipped: dict[str, Any] = {}
    try:
        previous_results = db.meta()["sources"]
        now = datetime.now(timezone.utc)
        for key in sources:
            spec = SOURCES[key]
            polite = _polite_skip(key, previous_results.get(key), now)
            if polite is not None:  # not recorded: keeps the time of the last real download
                skipped[key] = {**polite, "at_utc": _utc_now()}
                if progress:
                    progress(key, f"{spec['title']}: {polite['status']}")
                continue
            if progress:
                progress(key, f"جاري تنزيل {spec['title']}...")
            try:
                if key == "upx_tool":
                    from .unpacker import UPX_EXE
                    if os.name != "nt" or UPX_EXE.exists():
                        results[key] = {"status": "UPDATED" if UPX_EXE.exists() else "EMPTY", "added": {}, "at_utc": _utc_now()}
                        continue  # installed once; Windows build only
                    raw = fetch(spec["url"])
                    if raw[:2] != b"MZ":
                        raise ValueError("Downloaded UPX is not a Windows executable")
                    UPX_EXE.parent.mkdir(parents=True, exist_ok=True)
                    UPX_EXE.write_bytes(raw)
                    results[key] = {"status": "UPDATED", "added": {"tools": 1}, "at_utc": _utc_now()}
                    continue
                if spec.get("unavailable"):
                    results[key] = {"status": "NOT_AVAILABLE", "detail": spec["unavailable"], "at_utc": _utc_now()}
                    continue
                url = spec["url"]
                if spec.get("keyed"):
                    if not auth_key and real_download:
                        raise DownloadError("AUTH_REQUIRED", "abuse.ch Auth-Key needed (auth.abuse.ch)")
                    url = url.format(key=urllib.parse.quote(auth_key or "NO-KEY", safe=""))
                try:
                    raw = fetch(url)
                except DownloadError as exc:  # never let the key (now in the URL) reach logs
                    raise DownloadError(exc.status, _redact(str(exc), auth_key)) from None
                text = raw.decode("utf-8", errors="replace")
                before = db.counts()
                keep = key in ACCUMULATING_SOURCES
                if key.startswith("malwarebazaar"):
                    added = db.replace_source(key, hashes=parse_malwarebazaar_csv(text, key), keep_existing=keep)
                elif key == "threatfox":
                    added = db.replace_source(key, keep_existing=keep, **parse_threatfox(text, key))
                    db.prune_network_iocs(key, NETWORK_IOC_MAX_AGE_DAYS)
                elif key == "feodo":
                    added = db.replace_source(key, ips=parse_feodo_json(text, key))
                elif key == "urlhaus":
                    added = db.replace_source(key, **parse_urlhaus_csv(text, key))
                elif key == "sslbl":
                    added = db.replace_source(key, ips=parse_sslbl_csv(text, key))
                elif key == "openphish":
                    added = db.replace_source(key, **parse_url_list(text, key))
                elif key == "yara_forge_core":
                    added = {"yara_rules": install_yara_rules(text, "yara-forge-core.yar")}
                else:
                    continue
                total = sum(added.values())
                after = db.counts()
                results[key] = {"status": "UPDATED" if total else "EMPTY", "added": added, "at_utc": _utc_now(),
                                "new": {k: max(0, after[k] - before[k]) for k in after} if key != "yara_forge_core" else {}}
            except DownloadError as exc:
                results[key] = {"status": exc.status, "detail": str(exc), "at_utc": _utc_now()}
            except (ValueError, csv.Error, zipfile.BadZipFile, sqlite3.Error, OSError, Exception) as exc:
                results[key] = {"status": "PARSE_ERROR", "detail": _redact(f"{type(exc).__name__}: {exc}", auth_key),
                                "at_utc": _utc_now()}
            if progress:
                progress(key, f"{spec['title']}: {results[key]['status']}")
        db.record_update(results)
        return {"sources": {**results, **skipped}, "counts": db.counts(), "updated_at_utc": _utc_now()}
    finally:
        if own_db:
            db.close()


def install_yara_rules(text: str, name: str) -> int:
    """Validate (compile) and atomically install a downloaded YARA rule file."""
    if "rule " not in text:
        raise ValueError("Downloaded file does not contain YARA rules")
    from .yara_engine import RULES_DIR, available, validate_source
    if available():
        validate_source(text)
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    target = RULES_DIR / name
    tmp = target.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(target)
    return text.count("\nrule ") + text.count("\nprivate rule ")


class CombinedSignatures:
    """Local JSON signatures first, then the threat-intel database; dict-like ``get``."""

    def __init__(self, local: dict, db: ThreatIntelDB | None):
        self.local, self.db = local or {}, db

    def get(self, sha256: str, default=None):
        hit = self.local.get(sha256)
        if hit is None and self.db is not None:
            hit = self.db.get(sha256)
        return default if hit is None else hit

    def __len__(self) -> int:
        return len(self.local) + (len(self.db) if self.db is not None else 0)


def open_default_db() -> ThreatIntelDB | None:
    """Open the database if it exists; never creates an empty one during a scan."""
    if not DEFAULT_DB.exists():
        return None
    try:
        return ThreatIntelDB(DEFAULT_DB)
    except sqlite3.Error:
        return None


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Update the EagleGuard threat-intel database")
    parser.add_argument("--full", action="store_true", help="also download the full MalwareBazaar dump (large)")
    parser.add_argument("--auth-key", help="abuse.ch Auth-Key (free; or set ABUSE_CH_AUTH_KEY)")
    args = parser.parse_args()
    sources = list(DEFAULT_SOURCES) + (["malwarebazaar_full"] if args.full else [])
    report = update_all(sources=sources, auth_key=args.auth_key,
                        progress=lambda key, msg: print(msg, flush=True))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if any(r["status"] == "UPDATED" for r in report["sources"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
