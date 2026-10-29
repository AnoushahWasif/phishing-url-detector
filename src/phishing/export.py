"""Train the served model and write it with its manifest. Run at image build time."""

import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import sklearn

from phishing.metrics import evaluate
from phishing.model_store import MANIFEST_FILE, MODEL_FILE, SERVED_MODEL, sha256
from phishing.train import fit_all


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


if __name__ == "__main__":
    print(json.dumps(export(), indent=2))
