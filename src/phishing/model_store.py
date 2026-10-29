"""Load the served model only if its hash matches the manifest or deploy config.

joblib files are pickles, and unpickling runs code. So the hash is checked before
joblib.load ever touches the file. Nothing here imports training code, so the API
image doesn't need it.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

import joblib

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
