# Classifier training

Section VI.D of the report describes a Random Forest trained on CIC-IDS2017
with an 80/20 split, evaluated on accuracy, precision, recall, F1 and a
confusion matrix. Until this pipeline is run, none of that has happened: the
model is fitted at startup on Gaussian noise and every API response carries
`model_source: "synthetic"` to say so.

## Running it

1. Download CIC-IDS2017 from <https://www.unb.ca/cic/datasets/ids-2017.html>
   (the `MachineLearningCVE/` CSVs, several GB).
2. From `backend/`:

   ```bash
   python -m ml.train --data /path/to/MachineLearningCVE/
   ```

   Add `--max-per-class 50000` for a faster first pass on a laptop.

3. Two files land beside `MODEL_PATH_RF`: the fitted model, and
   `random_forest_model_metrics.json`. **Quote the JSON in the report** — those
   are measurements, and anything else is an estimate.

`python -m ml.train --evaluate-only` reprints the saved metrics without
retraining.

## What the numbers will and will not tell you

Two things to be straight about in the report, because a reader who knows the
dataset will ask:

**Domain shift.** CIC-IDS2017 is *network flow* data. This honeypot captures
*application sessions with commands*, and `FeatureExtractor.extract_from_raw`
synthesises flow-shaped features from them. A model trained here is measured on
flows and applied to approximations of flows. The metrics are real; their
transfer to live honeypot traffic is an assumption, and should be stated as
one rather than implied away.

**The classes are folded.** CIC-IDS2017's labels do not line up with the four
this system reports, so `ml/cicids.py` maps them: port scans to
reconnaissance, the patator/DoS/web-attack families to exploitation, Bot and
Infiltration to exfiltration. Labels with no mapping are dropped rather than
guessed at. That mapping is a design decision worth defending in the report,
not an implementation detail.

Training on captured honeypot sessions avoids the domain shift entirely and is
the better long-term path — but it needs the engine to have run first.
