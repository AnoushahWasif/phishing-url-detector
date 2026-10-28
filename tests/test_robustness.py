import pandas as pd
import pytest

from phishing.attacks import ATTACKS
from phishing.data import hostname
from phishing.robustness import evasion_table
from phishing.train import fit_all


def synthetic_df(n=600):
    urls, labels = [], []
    for i in range(n):
        if i % 2:
            urls.append(f"https://secure-login-{i}.verify{i % 7}.xyz/")
        else:
            urls.append(f"https://www.brand{i}.com/")
        labels.append(i % 2)
    return pd.DataFrame(
        {"url": urls, "hostname": [hostname(u) for u in urls], "is_phishing": labels}
    )


@pytest.fixture(scope="module")
def table():
    return evasion_table(fit_all(synthetic_df()))


def test_one_row_per_model_and_attack(table):
    assert len(table) == 4 * len(ATTACKS)
    assert set(table["attack"]) == set(ATTACKS)


def test_rates_are_valid(table):
    assert table["evasion_rate"].between(0, 1).all()
    assert (table["evaded"] <= table["caught_before"]).all()


def test_long_path_never_changes_a_verdict(table):
    # Hostname-only features: the control attack must evade nothing.
    assert (table.loc[table["attack"] == "long_path", "evaded"] == 0).all()
