import json
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from phishing.data import load
from phishing.features import CATEGORICAL_FEATURES, NUMERIC_FEATURES, TEXT_FEATURE, extract_many
from phishing.metrics import evaluate, threshold_at_fpr
from phishing.plots import plot_recall_vs_fpr
from phishing.split import grouped_split

SEED = 42
REPORTS = Path("reports")


def tld_encoder() -> OneHotEncoder:
    # 570 TLDs: rare ones share one "infrequent" column instead of hundreds of near-empty ones.
    return OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=50)


def char_ngrams() -> TfidfVectorizer:
    # Character 2-5 grams of the hostname: picks up pieces like "paypa", "-secure", "xn--"
    # without anyone writing a rule for them. min_df drops grams seen in only a couple of
    # hosts, which would otherwise memorise individual training domains.
    return TfidfVectorizer(
        analyzer="char", ngram_range=(2, 5), min_df=5, sublinear_tf=True, dtype=np.float32
    )


def models() -> dict[str, Pipeline]:
    linear = ColumnTransformer(
        [("num", StandardScaler(), NUMERIC_FEATURES), ("tld", tld_encoder(), CATEGORICAL_FEATURES)]
    )
    trees = ColumnTransformer(
        [("num", "passthrough", NUMERIC_FEATURES), ("tld", tld_encoder(), CATEGORICAL_FEATURES)]
    )
    text = ColumnTransformer([("chars", char_ngrams(), TEXT_FEATURE)])
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
        "lightgbm": make_pipeline(
            trees,
            LGBMClassifier(
                n_estimators=400,
                learning_rate=0.05,
                num_leaves=63,
                min_child_samples=50,
                random_state=SEED,
                verbose=-1,
            ),
        ),
        "char_ngram_logreg": make_pipeline(
            text, LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")
        ),
    }


@dataclass
class Trained:
    models: dict[str, Pipeline]
    thresholds: dict[str, float]
    test: pd.DataFrame
    X_test: pd.DataFrame
    fit_seconds: dict[str, float]


def fit_all(df: pd.DataFrame | None = None, only: list[str] | None = None) -> Trained:
    df = load() if df is None else df
    train, test = grouped_split(df, seed=SEED)
    # Threshold comes from a separate validation slice: a model's scores on its own
    # training rows are over-confident, so a threshold picked there misses the FPR target.
    fit, val = grouped_split(train, test_size=0.2, seed=SEED)
    X_fit, X_val, X_test = (extract_many(part["url"]) for part in (fit, val, test))
    y_fit, y_val = (part["is_phishing"].to_numpy() for part in (fit, val))

    fitted, thresholds, seconds = {}, {}, {}
    for name, model in models().items():
        if only is not None and name not in only:
            continue
        start = time.perf_counter()
        fitted[name] = model.fit(X_fit, y_fit)
        seconds[name] = round(time.perf_counter() - start, 1)
        thresholds[name] = threshold_at_fpr(y_val, model.predict_proba(X_val)[:, 1])
    return Trained(fitted, thresholds, test, X_test, seconds)


def run() -> pd.DataFrame:
    trained = fit_all()
    y_test = trained.test["is_phishing"].to_numpy()
    rows, test_scores = [], {}
    for name, model in trained.models.items():
        start = time.perf_counter()
        scores = model.predict_proba(trained.X_test)[:, 1]
        ms_per_1k = (time.perf_counter() - start) / len(trained.X_test) * 1e6
        test_scores[name] = scores
        rows.append(
            {
                "model": name,
                "fit_seconds": trained.fit_seconds[name],
                "ms_per_1k_urls": round(ms_per_1k, 2),
                **evaluate(y_test, scores, trained.thresholds[name]),
            }
        )
        print(f"{name}: recall {rows[-1]['recall']:.3f}, fpr {rows[-1]['false_positive_rate']:.4f}")

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "model_comparison.json").write_text(json.dumps(rows, indent=2))
    plot_recall_vs_fpr(y_test, test_scores, REPORTS / "figures" / "recall_vs_fpr.png")
    return pd.DataFrame(rows)


if __name__ == "__main__":
    print(run().round(4).to_string(index=False))
