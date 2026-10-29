"""Save the served model next to a manifest, and load it back only if its hash matches.

joblib files are pickles, and unpickling runs code. So the hash is checked before
joblib.load ever touches the file.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import joblib
import sklearn

from phishing.metrics import evaluate
from phishing.train import fit_all

SERVED_MODEL = "char_ngram_logreg"
MODEL_FILE, MANIFEST_FILE = "model.joblib", "model.json"


class ModelIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedModel:
    model: object
    threshold: float
    manifest: dict


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def export(out_dir: Path = Path("models"), df=None) -> dict:
    trained = fit_all(df, only=[SERVED_MODEL])
    model, threshold = trained.models[SERVED_MODEL], trained.thresholds[SERVED_MODEL]
    test_scores = model.predict_proba(trained.X_test)[:, 1]
    metrics = evaluate(trained.test["is_phishing"].to_numpy(), test_scores, threshold)

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / MODEL_FILE
    joblib.dump(model, path)
    manifest = {
        "model": SERVED_MODEL,
        "threshold": threshold,
        "sha256": sha256(path),
        "sklearn_version": sklearn.__version__,
        "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "test_recall": round(metrics["recall"], 4),
        "test_false_positive_rate": round(metrics["false_positive_rate"], 4),
    }
    (out_dir / MANIFEST_FILE).write_text(json.dumps(manifest, indent=2))
    return manifest


def load_model(model_dir: Path, expected_sha256: str | None = None) -> LoadedModel:
    """Refuse to load unless the file matches the expected hash.

    `expected_sha256` comes from deploy config when given; otherwise the manifest's hash
    is used, which still catches a model file swapped or corrupted on its own.
    """
    try:
        manifest = json.loads((model_dir / MANIFEST_FILE).read_text())
        expected = (expected_sha256 or manifest["sha256"]).lower()
        threshold = float(manifest["threshold"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ModelIntegrityError("model manifest missing or unreadable") from exc
    if not 0.0 < threshold <= 1.0:
        raise ModelIntegrityError("threshold in manifest is out of range")

    path = model_dir / MODEL_FILE
    if not path.is_file():
        raise ModelIntegrityError("model file missing")
    if not hmac.compare_digest(sha256(path), expected):
        raise ModelIntegrityError("model file hash does not match; refusing to load it")
    return LoadedModel(joblib.load(path), threshold, manifest)


if __name__ == "__main__":
    print(json.dumps(export(), indent=2))
