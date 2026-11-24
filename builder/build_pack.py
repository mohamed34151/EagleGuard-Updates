"""Build the signed EagleGuard signature package.

    python builder/build_pack.py <out_dir> <work_dir>

Env: ABUSE_CH_AUTH_KEY (abuse.ch Auth-Key), EAGLEGUARD_SIGNING_KEY (Ed25519 private key, base64 raw 32 bytes).
The previous package is downloaded first so the database keeps accumulating.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import sqlite3
import sys
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT, WORK = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
WORK.mkdir(parents=True, exist_ok=True)
os.environ["EG_BUILD_DIR"] = str(WORK)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from eg_updater import signature_updater as su  # noqa: E402

PREVIOUS = "https://raw.githubusercontent.com/{repo}/dist/threat_intel.db.gz".format(
    repo=os.environ.get("GITHUB_REPOSITORY", "mohamed34151/EagleGuard-Updates"))
SOURCES = ("malwarebazaar_recent", "threatfox", "feodo", "urlhaus", "sslbl", "openphish", "yara_forge_core")
MIN_HASHES = 100  # never publish an (almost) empty database


def main() -> int:
    db_path = WORK / "threat_intel.db"
    try:
        with urllib.request.urlopen(urllib.request.Request(PREVIOUS, headers={"Cache-Control": "no-cache"}),
                                    timeout=180) as response:
            db_path.write_bytes(gzip.decompress(response.read()))
        print("previous package restored")
    except Exception as exc:
        print(f"no previous package ({type(exc).__name__}); starting fresh")
    su.DEFAULT_MIN_INTERVAL = timedelta(minutes=50)  # the schedule runs every 2 hours
    db = su.ThreatIntelDB(db_path)
    report = su.update_all(db, sources=SOURCES, auth_key=os.environ.get("ABUSE_CH_AUTH_KEY") or None)
    counts = db.counts()
    db.close()
    statuses = {k: {"status": v.get("status"), "detail": v.get("detail")} for k, v in report["sources"].items()}
    print(json.dumps({"counts": counts, "sources": statuses}, ensure_ascii=False, indent=1))
    if counts["hashes"] < MIN_HASHES:
        print("refusing to publish: database too small")
        return 1
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute("VACUUM")
    files = {"threat_intel.db.gz": gzip.compress(db_path.read_bytes(), 9)}
    rules = WORK / "yara" / "yara-forge-core.yar"
    if rules.exists():
        files["yara-forge-core.yar.gz"] = gzip.compress(rules.read_bytes(), 9)
    now = datetime.now(timezone.utc)
    payload = {"format": 1, "version": now.strftime("%Y%m%dT%H%M%SZ"), "created_utc": now.isoformat(timespec="seconds"),
               "counts": counts, "sources": statuses,
               "files": {name: {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)}
                         for name, blob in files.items()}}
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(os.environ["EAGLEGUARD_SIGNING_KEY"].strip()))
    signature = base64.b64encode(key.sign(text.encode("utf-8"))).decode()
    for name, blob in files.items():
        (OUT / name).write_bytes(blob)
    (OUT / "manifest.json").write_text(json.dumps({"payload": text, "signature": signature}, ensure_ascii=False),
                                       encoding="utf-8")
    print("package", payload["version"], {n: len(b) for n, b in files.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
