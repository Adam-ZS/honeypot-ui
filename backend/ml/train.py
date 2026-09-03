"""Train and evaluate the attack classifier.

Section VI.D of the report describes a Random Forest trained on CIC-IDS2017
with an 80/20 split, evaluated on accuracy, precision, recall, F1 and a
confusion matrix. None of that existed: the shipped model was fitted at
startup on ``np.random.normal`` vectors, and no evaluation code was present
anywhere, so the reported "high classification performance" measured nothing.

This is that pipeline. Run it and the claim becomes true; until it is run, the
API keeps reporting ``model_source: "synthetic"`` so no verdict is presented
as trained.

    # Download CIC-IDS2017 CSVs first (they are several GB):
    #   https://www.unb.ca/cic/datasets/ids-2017.html
    python -m ml.train --data /path/to/MachineLearningCVE/

    # Cap per-class rows for a faster pass on a laptop:
    python -m ml.train --data ./MachineLearningCVE/ --max-per-class 50000

    # Report metrics for the current artefact without retraining:
    python -m ml.train --evaluate-only

Writes the fitted model to MODEL_PATH_RF and a JSON metrics report beside it,
so the numbers quoted in the report have a file behind them.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ai.classifier import ATTACK_LABELS, FeatureExtractor  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from ml import cicids  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("train")

#: The report specifies 80/20.
TEST_SIZE = 0.20
RANDOM_STATE = 42


def _assert_feature_alignment() -> None:
    """Training and inference must agree on what each vector position means.

    A silent divergence here is unfalsifiable from the metrics: the model would
    score well on its own split and be nonsense in production.
    """
    if cicids.FEATURES != FeatureExtractor.CICIDS_FEATURES:
        raise SystemExit(
            "Feature order has diverged between ml/cicids.py and the "
            "classifier's FeatureExtractor. Training would produce a model "
            "whose inputs mean something different at inference time."
        )


def evaluate(model, label_encoder, X_test, y_test) -> dict:
    """Per-class precision/recall/F1 plus a confusion matrix.

    Per-class, not just headline accuracy: the expert interviews recorded in
    §V.B.2 said exactly this, and on an imbalanced set a model that predicts
    the majority class every time still scores well on accuracy alone.
    """
    y_pred = model.predict(X_test)
    labels_present = sorted(set(y_test) | set(y_pred))
    names = list(label_encoder.inverse_transform(labels_present))

    report = classification_report(
        y_test, y_pred, labels=labels_present, target_names=names,
        output_dict=True, zero_division=0,
    )
    matrix = confusion_matrix(y_test, y_pred, labels=labels_present)

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_test": int(len(y_test)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "per_class": {
            name: {
                "precision": float(report[name]["precision"]),
                "recall": float(report[name]["recall"]),
                "f1": float(report[name]["f1-score"]),
                "support": int(report[name]["support"]),
            }
            for name in names
        },
        "confusion_matrix": {"labels": names, "matrix": matrix.tolist()},
    }
    return metrics


def print_metrics(m: dict) -> None:
    print()
    print(f"  Test samples      {m['n_test']:,}")
    print(f"  Accuracy          {m['accuracy']:.4f}")
    print(f"  Precision (macro) {m['precision_macro']:.4f}")
    print(f"  Recall (macro)    {m['recall_macro']:.4f}")
    print(f"  F1 (macro)        {m['f1_macro']:.4f}")
    print()
    print(f"  {'class':<18}{'precision':>10}{'recall':>10}{'f1':>10}{'support':>10}")
    for name, s in m["per_class"].items():
        print(f"  {name:<18}{s['precision']:>10.4f}{s['recall']:>10.4f}"
              f"{s['f1']:>10.4f}{s['support']:>10,}")

    print()
    labels = m["confusion_matrix"]["labels"]
    width = max(len(x) for x in labels) + 2
    print("  Confusion matrix (rows = actual, columns = predicted)")
    print("  " + " " * width + "".join(f"{x[:8]:>10}" for x in labels))
    for name, row in zip(labels, m["confusion_matrix"]["matrix"]):
        print(f"  {name:<{width}}" + "".join(f"{v:>10,}" for v in row))
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", help="CIC-IDS2017 CSV file or directory")
    parser.add_argument("--max-per-class", type=int, default=None,
                        help="Cap rows per class; useful for a quick pass")
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=20)
    parser.add_argument("--evaluate-only", action="store_true",
                        help="Report metrics for the saved artefact, no training")
    args = parser.parse_args()

    _assert_feature_alignment()
    settings = get_settings()
    model_path = settings.MODEL_PATH_RF
    metrics_path = os.path.splitext(model_path)[0] + "_metrics.json"

    if args.evaluate_only:
        if not os.path.exists(metrics_path):
            print(f"No metrics report at {metrics_path}. Train first.")
            return 1
        print_metrics(json.load(open(metrics_path)))
        return 0

    if not args.data:
        parser.error("--data is required unless --evaluate-only is given")

    logger.info("Loading dataset from %s", args.data)
    X, y = cicids.load(args.data, max_rows_per_class=args.max_per_class)

    classes, counts = np.unique(y, return_counts=True)
    logger.info("Class balance: %s", dict(zip(classes, counts.tolist())))
    missing = set(ATTACK_LABELS) - set(classes)
    if missing:
        logger.warning(
            "No examples for %s — the model cannot predict what it never saw, "
            "and the report should say which classes were trainable.", sorted(missing),
        )

    encoder = LabelEncoder().fit(y)
    y_encoded = encoder.transform(y)

    # Stratified so rare classes survive the split; without it a small class
    # can land entirely in one side and its recall becomes meaningless.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_encoded,
    )
    logger.info("Split: %d train / %d test (%.0f%% held out)",
                len(X_train), len(X_test), TEST_SIZE * 100)

    model = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_split=5,
        min_samples_leaf=2,
        # CIC-IDS2017 is heavily benign-dominated. Without this the model can
        # score high accuracy by rarely predicting an attack at all — the
        # false-negative failure Sommer & Paxson [7] warn about.
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    logger.info("Fitting %d trees...", args.n_estimators)
    model.fit(X_train, y_train)

    metrics = evaluate(model, encoder, X_test, y_test)
    metrics["training"] = {
        "source": "cicids2017",
        "n_train": int(len(X_train)),
        "test_size": TEST_SIZE,
        "n_estimators": args.n_estimators,
        "max_depth": args.max_depth,
        "class_weight": "balanced_subsample",
    }
    metrics["top_features"] = [
        {"feature": cicids.FEATURES[i], "importance": float(model.feature_importances_[i])}
        for i in np.argsort(model.feature_importances_)[::-1][:10]
    ]

    os.makedirs(os.path.dirname(model_path) or ".", exist_ok=True)
    with open(model_path, "wb") as fh:
        pickle.dump(
            {"model": model, "label_encoder": encoder, "source": "cicids2017"}, fh
        )
    with open(metrics_path, "w") as fh:
        json.dump(metrics, fh, indent=2)

    print_metrics(metrics)
    print(f"  model   -> {model_path}")
    print(f"  metrics -> {metrics_path}")
    print("\n  The API will now report model_source: \"cicids2017\" instead of")
    print("  \"synthetic\". Quote these numbers in the report, not estimates.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
