import json

import numpy as np
import pandas as pd

from phishing.attacks import ATTACKS
from phishing.features import extract_many
from phishing.train import REPORTS, Trained, fit_all


def evasion_table(trained: Trained) -> pd.DataFrame:
    """For each model and attack: share of caught phishing that drops below the threshold."""
    test = trained.test.reset_index(drop=True)
    phishing = (test["is_phishing"] == 1).to_numpy()

    caught_by = {}
    for name, model in trained.models.items():
        scores = model.predict_proba(trained.X_test)[:, 1]
        caught_by[name] = phishing & (scores >= trained.thresholds[name])

    # Attack every phishing host once; each model then only looks at the ones it caught.
    hosts = test.loc[phishing, "hostname"].to_numpy()
    index = np.flatnonzero(phishing)
    attacked = {attack: extract_many(fn(h) for h in hosts) for attack, fn in ATTACKS.items()}

    rows = []
    for name, model in trained.models.items():
        mask = caught_by[name][index]
        for attack, X in attacked.items():
            scores = model.predict_proba(X[mask])[:, 1]
            rows.append(
                {
                    "model": name,
                    "attack": attack,
                    "caught_before": int(mask.sum()),
                    "evaded": int((scores < trained.thresholds[name]).sum()),
                    "evasion_rate": float((scores < trained.thresholds[name]).mean()),
                }
            )
    return pd.DataFrame(rows)


def run(tag: str = "baseline") -> pd.DataFrame:
    table = evasion_table(fit_all())
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / f"robustness_{tag}.json").write_text(
        json.dumps(table.to_dict(orient="records"), indent=2)
    )
    return table


if __name__ == "__main__":
    import sys

    table = run(sys.argv[1] if len(sys.argv) > 1 else "baseline")
    print(table.pivot(index="attack", columns="model", values="evasion_rate").round(3))
