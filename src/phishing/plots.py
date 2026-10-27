from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.metrics import roc_curve  # noqa: E402

from phishing.metrics import MAX_FPR  # noqa: E402

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e5e1"


def spread_labels(ys: dict[str, float], min_gap: float = 3.5) -> dict[str, float]:
    """Push end-of-line label positions apart so close curves don't print on top of each other."""
    placed: dict[str, float] = {}
    for name, y in sorted(ys.items(), key=lambda item: item[1]):
        floor = max(placed.values(), default=float("-inf")) + min_gap
        placed[name] = max(y, floor)
    return placed


def plot_recall_vs_fpr(y_true, scores_by_model: dict, path: Path, max_x: float = 0.05) -> None:
    """ROC curve zoomed to the low false-positive range, where the operating point lives."""
    if len(scores_by_model) > len(SERIES):
        raise ValueError(f"At most {len(SERIES)} models per chart")
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=150)
    ends = {}
    for color, (name, scores) in zip(SERIES, scores_by_model.items(), strict=False):
        fpr, tpr, _ = roc_curve(y_true, scores)
        keep = fpr <= max_x
        ax.plot(fpr[keep] * 100, tpr[keep] * 100, color=color, lw=2, label=name)
        ends[name] = (fpr[keep][-1] * 100, tpr[keep][-1] * 100)

    for name, y in spread_labels({n: y for n, (_, y) in ends.items()}).items():
        ax.annotate(
            name,
            (ends[name][0], y),
            xytext=(4, 0),
            textcoords="offset points",
            va="center",
            fontsize=8,
            color=INK,
        )

    ax.axvline(MAX_FPR * 100, color=MUTED, lw=1, ls="--")
    ax.text(MAX_FPR * 100 + 0.08, 3, "1% false-alarm budget", color=MUTED, fontsize=8)
    ax.set_xlim(0, max_x * 100 * 1.35)
    ax.set_ylim(0, 100)
    ax.set_xlabel("Legitimate sites flagged (%)", color=MUTED)
    ax.set_ylabel("Phishing caught (%)", color=MUTED)
    ax.set_title(
        "Recall at low false-positive rates, domain-grouped test set", color=INK, loc="left"
    )
    ax.grid(color=GRID, lw=0.8)
    ax.tick_params(colors=MUTED)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
