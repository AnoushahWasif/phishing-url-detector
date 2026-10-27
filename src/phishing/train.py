import json
import time
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from phishing.data import load
from phishing.features import CATEGORICAL_FEATURES, NUMERIC_FEATURES, extract_many
from phishing.metrics import evaluate, threshold_at_fpr
from phishing.split import grouped_split

SEED = 42
REPORTS = Path("reports")


def tld_encoder() -> OneHotEncoder:
    # 570 TLDs: rare ones share one "infrequent" column instead of hundreds of near-empty ones.
    return OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=50)


def models() -> dict[str, Pipeline]:
    linear = ColumnTransformer(
        [("num", StandardScaler(), NUMERIC_FEATURES), ("tld", tld_encoder(), CATEGORICAL_FEATURES)]
    )
    trees = ColumnTransformer(
        [("num", "passthrough", NUMERIC_FEATURES), ("tld", tld_encoder(), CATEGORICAL_FEATURES)]
    )
    return {
        "logistic_regression": make_pipeline(
            linear, LogisticRegression(max_iter=2000, class_weight="balanced")
        ),
        "random_forest": make_pipeline(
            trees,
            RandomForestClassifier(
                n_estimators=200, min_samples_leaf=5, n_jobs=-1, random_state=SEED
            ),
        ),
    }


def run() -> pd.DataFrame:
    df = load()
    train, test = grouped_split(df, seed=SEED)
    # Threshold comes from a separate validation slice: a model's scores on its own
    # training rows are over-confident, so a threshold picked there misses the FPR target.
    fit, val = grouped_split(train, test_size=0.2, seed=SEED)
    X_fit, X_val, X_test = (extract_many(part["url"]) for part in (fit, val, test))
    y_fit, y_val, y_test = (part["is_phishing"].to_numpy() for part in (fit, val, test))

    rows = []
    for name, model in models().items():
        start = time.perf_counter()
        model.fit(X_fit, y_fit)
        fit_seconds = time.perf_counter() - start

        threshold = threshold_at_fpr(y_val, model.predict_proba(X_val)[:, 1])
        result = evaluate(y_test, model.predict_proba(X_test)[:, 1], threshold)
        rows.append({"model": name, "fit_seconds": round(fit_seconds, 1), **result})

    results = pd.DataFrame(rows)
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "baselines.json").write_text(json.dumps(rows, indent=2))
    return results


if __name__ == "__main__":
    print(run().round(4).to_string(index=False))
