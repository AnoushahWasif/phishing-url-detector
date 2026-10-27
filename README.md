# Phishing URL detector

> Work in progress. Started October 2026.

Flags phishing links from the URL text alone, without opening the page. Trained on the [PhiUSIIL Phishing URL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI, about 235k URLs, 57% legitimate and 43% phishing), served through a small API, and used by a Chrome extension that warns before you land on a risky page.

URL-only matters for two reasons: it's fast enough to run before a page loads, and it never fetches anything from an attacker's server. The cost is less information to work with, and the project measures how much accuracy that costs.

## Early finding: the dataset has a shortcut

Every legitimate URL in PhiUSIIL is a bare homepage like `https://www.example.org`, and none of them have a path or sit on free hosting. A one-line regex ("is it a bare `https://www.` homepage?") gets **99.56% accuracy** with no machine learning at all. Models trained on raw URLs would learn that formatting difference instead of phishing, so this project trains on the **hostname only** and reports results there. Details in [notebooks/01_eda.ipynb](notebooks/01_eda.ipynb).

## Results so far (hostname only, test domains never seen in training)

Threshold chosen on a validation slice for at most 1% false alarms, then applied unchanged to the test set (47k URLs).

| Model | Phishing caught | Missed | False-alarm rate | PR-AUC | Fit time |
|-------|-----------------|--------|------------------|--------|----------|
| Logistic regression (11 features + TLD) | 57.9% | 7,583 | 1.15% | 0.874 | 4 s |
| Random forest (same features) | 60.3% | 7,148 | 0.92% | 0.880 | 61 s |
| LightGBM (same features) | 61.7% | 6,889 | 1.00% | 0.885 | 8 s |
| Character 2–5 grams of the hostname + logistic regression | **62.5%** | **6,749** | 0.99% | **0.908** | 9 s |

![Recall against false-alarm rate for the four models](reports/figures/recall_vs_fpr.png)

- At the 1% budget the four models are within 5 points of each other. The hand-made features have run out of signal more than the models have run out of capacity.
- The character model needs no feature code at all and is the best at every false-alarm rate above about 0.7%. Its ROC-AUC is 0.910 against 0.874–0.884 for the rest, so it ranks the "hard middle" better.
- LightGBM matches the random forest's recall at an eighth of the training time.
- A random row split instead of the domain split would have reported 61.9% and 65.9% for the first two: 4–6 points too optimistic, because the model gets to see other pages of the same domains in training.

These are still unflattering numbers. With the hostname alone, roughly 40% of phishing hosts look ordinary (`maria.susypro.com`). Day 6 attacks the models on purpose (homoglyphs, shorteners, padded subdomains) to see where each one breaks.

## Plan

- [x] EDA: URL length, TLDs, subdomains, HTTPS, class balance
- [x] URL-only feature extractor with tests
- [x] Baselines (logistic regression, random forest), judged mostly on missed phishing
- [x] LightGBM and a character-level model on the hostname text
- [ ] Robustness: homoglyphs, URL shorteners, long paths. Where does it break?
- [ ] FastAPI `/score` endpoint + Docker
- [ ] Chrome extension (TypeScript, Manifest V3)
- [ ] CI with security scans

## Stack

Python 3.12, pandas, scikit-learn, LightGBM, FastAPI, TypeScript (extension), pytest, ruff, uv.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). It includes a threat model focused on how attackers would try to get past the detector.

## License

MIT
