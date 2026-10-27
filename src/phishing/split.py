from functools import cache

import pandas as pd
import tldextract
from sklearn.model_selection import GroupShuffleSplit

# Offline: use the suffix list bundled with tldextract, never fetch it at runtime.
# Private suffixes on, so abc.web.app and xyz.web.app count as different owners.
_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


@cache
def registered_domain(host: str) -> str:
    """example.com for a.b.example.com; the host itself for IPs and unparseable hosts."""
    return _extract(host).top_domain_under_public_suffix or host


def grouped_split(
    df: pd.DataFrame, test_size: float = 0.2, seed: int = 42
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Train/test split where no registered domain appears on both sides.

    A plain row split lets the model see login.example.com in training and
    secure.example.com in test, which tests memory, not generalisation.
    """
    groups = df["hostname"].map(registered_domain)
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(df, groups=groups))
    return df.iloc[train_idx], df.iloc[test_idx]
