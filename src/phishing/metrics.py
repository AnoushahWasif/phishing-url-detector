import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

MAX_FPR = 0.01


def threshold_at_fpr(y_true, scores, max_fpr: float = MAX_FPR) -> float:
    """Lowest score threshold whose false-positive rate stays at or under max_fpr."""
    fpr, _, thresholds = roc_curve(y_true, scores)
    ok = np.flatnonzero(fpr <= max_fpr)
    return float(thresholds[ok[-1]])


def evaluate(y_true, scores, threshold: float) -> dict:
    """Metrics at a fixed threshold. Label 1 = phishing."""
    y_true = np.asarray(y_true)
    pred = np.asarray(scores) >= threshold
    phishing, legit = y_true == 1, y_true == 0
    tp = int((pred & phishing).sum())
    fn = int((~pred & phishing).sum())
    fp = int((pred & legit).sum())
    tn = int((~pred & legit).sum())
    return {
        "threshold": float(threshold),
        "recall": tp / max(tp + fn, 1),
        "missed_phishing": fn,
        "false_positive_rate": fp / max(fp + tn, 1),
        "false_alarms": fp,
        "precision": tp / max(tp + fp, 1),
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "pr_auc": float(average_precision_score(y_true, scores)),
    }
