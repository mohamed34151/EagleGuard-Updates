"""Train EagleGuard's machine-learning detector on the public EMBER 2018 dataset.

Only byte-level features are used (EMBER's ByteHistogram, ByteEntropyHistogram and
StringExtractor = the first 616 EMBER features), because EagleGuard can compute exactly
these on every file in Rust, without extra libraries. The dataset contains features only,
no malware files.

    python trainer/train_ember.py <work_dir> <out_dir>
Output: <out_dir>/eagleguard-ml.json.gz (compact trees + threshold) and ml-metrics.json
"""
from __future__ import annotations

import gzip
import json
import os
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

import numpy as np

URLS = [
    "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2",
    "https://pubdata.endgame.com/ember/ember_dataset_2018_2.tar.bz2",
]


def strings_features(s: dict) -> list[float]:
    printables = float(s.get("printables", 0))
    divisor = printables if printables > 0 else 1.0
    dist = [float(x) / divisor for x in s.get("printabledist", [0] * 96)]
    return [float(s.get("numstrings", 0)), float(s.get("avlength", 0)), printables, *dist,
            float(s.get("entropy", 0)), float(s.get("paths", 0)), float(s.get("urls", 0)),
            float(s.get("registry", 0)), float(s.get("MZ", 0))]


def vectorize(obj: dict) -> np.ndarray:
    hist = np.asarray(obj["histogram"], dtype=np.float32)
    hist = hist / max(hist.sum(), 1.0)
    ent = np.asarray(obj["byteentropy"], dtype=np.float32)
    ent = ent / max(ent.sum(), 1.0)
    return np.concatenate([hist, ent, np.asarray(strings_features(obj["strings"]), dtype=np.float32)])


def download(work: Path) -> Path:
    target = work / "ember.tar.bz2"
    for url in URLS:
        try:
            print("downloading", url, flush=True)
            urllib.request.urlretrieve(url, target)
            if target.stat().st_size > 100_000_000:
                return target
        except Exception as exc:
            print("  failed:", exc, flush=True)
    raise SystemExit("EMBER dataset not reachable")


def load(archive: Path):
    X_train, y_train, X_test, y_test = [], [], [], []
    with tarfile.open(archive, "r:bz2") as tar:
        for member in tar:
            if not member.name.endswith(".jsonl"):
                continue
            is_test = "test_features" in member.name
            print("reading", member.name, flush=True)
            handle = tar.extractfile(member)
            for line in handle:
                obj = json.loads(line)
                label = obj.get("label", -1)
                if label not in (0, 1):
                    continue  # unlabeled
                (X_test if is_test else X_train).append(vectorize(obj))
                (y_test if is_test else y_train).append(label)
    return (np.vstack(X_train), np.asarray(y_train), np.vstack(X_test), np.asarray(y_test))


def compact(booster) -> dict:
    """LightGBM trees -> flat arrays. Node index >= 0 = split, < 0 = leaf (~index)."""
    trees = []
    for info in booster.dump_model()["tree_info"]:
        feat, thr, left, right, leaves = [], [], [], [], []

        def walk(node):
            if "leaf_value" in node:
                leaves.append(node["leaf_value"])
                return ~(len(leaves) - 1)
            index = len(feat)
            feat.append(node["split_feature"]); thr.append(node["threshold"]); left.append(0); right.append(0)
            assert node.get("decision_type", "<=") == "<="
            left[index] = walk(node["left_child"])
            right[index] = walk(node["right_child"])
            return index
        root = walk(info["tree_structure"])
        trees.append({"root": root, "f": feat, "t": thr, "l": left, "r": right, "v": leaves})
    return {"format": 1, "features": 616, "trees": trees}


def main() -> int:
    import lightgbm as lgb
    from sklearn.metrics import roc_auc_score, roc_curve
    work, out = Path(sys.argv[1]), Path(sys.argv[2])
    work.mkdir(parents=True, exist_ok=True); out.mkdir(parents=True, exist_ok=True)
    started = time.time()
    X, y, Xt, yt = load(download(work))
    print("train", X.shape, "test", Xt.shape, flush=True)
    model = lgb.LGBMClassifier(n_estimators=600, learning_rate=0.05, num_leaves=64, feature_fraction=0.5,
                               bagging_fraction=0.8, bagging_freq=1, min_child_samples=50, verbose=-1)
    model.fit(X, y)
    scores = model.predict_proba(Xt)[:, 1]
    auc = roc_auc_score(yt, scores)
    fpr, tpr, thresholds = roc_curve(yt, scores)
    picks = {}
    for target in (0.001, 0.005, 0.01):
        i = max(np.searchsorted(fpr, target, side="right") - 1, 0)
        picks[str(target)] = {"threshold": float(thresholds[i]), "detection": float(tpr[i]), "fpr": float(fpr[i])}
    data = compact(model.booster_)
    data["threshold"] = picks["0.005"]["threshold"]        # REVIEW level (0.5% false positives on EMBER test)
    data["threshold_high"] = picks["0.001"]["threshold"]   # HIGH level (0.1%)
    data["metrics"] = {"auc": float(auc), "operating_points": picks, "trained_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "dataset": "EMBER 2018 v2 (byte histogram + byte entropy + strings)", "train_rows": int(len(y))}
    # Reference vector so the client can check that its feature code matches.
    data["selftest"] = {"features": [float(v) for v in Xt[0]], "score": float(scores[0])}
    (out / "eagleguard-ml.json.gz").write_bytes(gzip.compress(json.dumps(data, separators=(",", ":")).encode(), 9))
    (out / "ml-metrics.json").write_text(json.dumps(data["metrics"], indent=1))
    print(json.dumps(data["metrics"], indent=1), "minutes", round((time.time() - started) / 60, 1), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
