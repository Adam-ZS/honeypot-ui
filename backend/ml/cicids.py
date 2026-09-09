"""CIC-IDS2017 adapter.

Maps the dataset's own column and label names onto the 36 features and four
classes the classifier already uses, so training and inference agree on what
each position in the vector means.

A caveat that belongs in the report rather than buried here: CIC-IDS2017 is
*network flow* data, while this honeypot captures *application sessions with
commands*. ``FeatureExtractor.extract_from_raw`` synthesises flow-shaped
features from session data to bridge that, which is a domain shift, not a
straightforward train-then-apply. A model trained here will be honest about
flows and approximate about sessions. Training on captured honeypot sessions
(``--source sessions``) avoids the shift entirely and is the better long-term
path; CIC-IDS2017 is supported because the report commits to it.
"""

from __future__ import annotations

import glob
import logging
import os
import re
from typing import Iterator, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

#: Feature order the classifier expects. Must stay identical to
#: FeatureExtractor.CICIDS_FEATURES — the training script asserts this.
FEATURES = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "fwd_packet_length_mean", "fwd_packet_length_std",
    "bwd_packet_length_mean", "bwd_packet_length_std",
    "flow_bytes_per_second", "flow_packets_per_second",
    "fwd_header_length", "bwd_header_length",
    "fwd_packets_per_second", "bwd_packets_per_second",
    "min_packet_length", "max_packet_length",
    "packet_length_mean", "packet_length_std", "packet_length_variance",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "down_up_ratio", "average_packet_size",
    "fwd_segment_size_mean", "bwd_segment_size_mean",
    "fwd_bytes_per_bulk", "fwd_bulk_rate",
    "subflow_fwd_packets", "subflow_bwd_packets",
    "active_mean", "active_std", "idle_mean", "idle_std",
]

#: CIC-IDS2017 ships columns with leading spaces and inconsistent casing, and
#: the exact spelling differs between the CICFlowMeter releases people have.
#: Keys here are normalised (lowercased, non-alphanumerics collapsed to "_").
_COLUMN_ALIASES = {
    "flow_duration": ["flow_duration"],
    "total_fwd_packets": ["total_fwd_packets", "tot_fwd_pkts"],
    "total_bwd_packets": ["total_backward_packets", "tot_bwd_pkts"],
    "fwd_packet_length_mean": ["fwd_packet_length_mean", "fwd_pkt_len_mean"],
    "fwd_packet_length_std": ["fwd_packet_length_std", "fwd_pkt_len_std"],
    "bwd_packet_length_mean": ["bwd_packet_length_mean", "bwd_pkt_len_mean"],
    "bwd_packet_length_std": ["bwd_packet_length_std", "bwd_pkt_len_std"],
    "flow_bytes_per_second": ["flow_bytes_s", "flow_byts_s"],
    "flow_packets_per_second": ["flow_packets_s", "flow_pkts_s"],
    "fwd_header_length": ["fwd_header_length", "fwd_header_len"],
    "bwd_header_length": ["bwd_header_length", "bwd_header_len"],
    "fwd_packets_per_second": ["fwd_packets_s", "fwd_pkts_s"],
    "bwd_packets_per_second": ["bwd_packets_s", "bwd_pkts_s"],
    "min_packet_length": ["min_packet_length", "pkt_len_min"],
    "max_packet_length": ["max_packet_length", "pkt_len_max"],
    "packet_length_mean": ["packet_length_mean", "pkt_len_mean"],
    "packet_length_std": ["packet_length_std", "pkt_len_std"],
    "packet_length_variance": ["packet_length_variance", "pkt_len_var"],
    "fin_flag_count": ["fin_flag_count", "fin_flag_cnt"],
    "syn_flag_count": ["syn_flag_count", "syn_flag_cnt"],
    "rst_flag_count": ["rst_flag_count", "rst_flag_cnt"],
    "psh_flag_count": ["psh_flag_count", "psh_flag_cnt"],
    "ack_flag_count": ["ack_flag_count", "ack_flag_cnt"],
    "urg_flag_count": ["urg_flag_count", "urg_flag_cnt"],
    "down_up_ratio": ["down_up_ratio"],
    "average_packet_size": ["average_packet_size", "pkt_size_avg"],
    "fwd_segment_size_mean": ["avg_fwd_segment_size", "fwd_seg_size_avg"],
    "bwd_segment_size_mean": ["avg_bwd_segment_size", "bwd_seg_size_avg"],
    "fwd_bytes_per_bulk": ["fwd_avg_bytes_bulk", "fwd_byts_b_avg"],
    "fwd_bulk_rate": ["fwd_avg_bulk_rate", "fwd_blk_rate_avg"],
    "subflow_fwd_packets": ["subflow_fwd_packets", "subflow_fwd_pkts"],
    "subflow_bwd_packets": ["subflow_bwd_packets", "subflow_bwd_pkts"],
    "active_mean": ["active_mean"],
    "active_std": ["active_std"],
    "idle_mean": ["idle_mean"],
    "idle_std": ["idle_std"],
}

#: CIC-IDS2017's attack labels folded onto the four classes the system reports.
#: Anything unmatched is dropped rather than guessed at — silently bucketing an
#: unknown label would corrupt the very metrics this exists to produce.
_LABEL_MAP = {
    "benign": "benign",
    "portscan": "reconnaissance",
    "port_scan": "reconnaissance",
    "ftp_patator": "exploitation",
    "ssh_patator": "exploitation",
    "web_attack_brute_force": "exploitation",
    "web_attack_xss": "exploitation",
    "web_attack_sql_injection": "exploitation",
    "heartbleed": "exploitation",
    "dos_hulk": "exploitation",
    "dos_goldeneye": "exploitation",
    "dos_slowloris": "exploitation",
    "dos_slowhttptest": "exploitation",
    "ddos": "exploitation",
    "infiltration": "exfiltration",
    "bot": "exfiltration",
}

#: Same clipping bounds the classifier applies at inference. Training on raw
#: magnitudes while inferring on [0,1] values was the defect that made the
#: shipped model's predictions arbitrary; both sides now use this one table.
SCALES = {
    "flow_duration": 600.0, "total_fwd_packets": 500.0, "total_bwd_packets": 500.0,
    "fwd_packet_length_mean": 1500.0, "fwd_packet_length_std": 1500.0,
    "bwd_packet_length_mean": 1500.0, "bwd_packet_length_std": 1500.0,
    "flow_bytes_per_second": 100000.0, "flow_packets_per_second": 500.0,
    "fwd_header_length": 500.0, "bwd_header_length": 500.0,
    "fwd_packets_per_second": 200.0, "bwd_packets_per_second": 200.0,
    "min_packet_length": 1500.0, "max_packet_length": 1500.0,
    "packet_length_mean": 1500.0, "packet_length_std": 1500.0,
    "packet_length_variance": 1000000.0,
    "fin_flag_count": 50.0, "syn_flag_count": 50.0, "rst_flag_count": 50.0,
    "psh_flag_count": 100.0, "ack_flag_count": 200.0, "urg_flag_count": 20.0,
    "down_up_ratio": 10.0, "average_packet_size": 1500.0,
    "fwd_segment_size_mean": 1500.0, "bwd_segment_size_mean": 1500.0,
    "fwd_bytes_per_bulk": 10000.0, "fwd_bulk_rate": 10000.0,
    "subflow_fwd_packets": 500.0, "subflow_bwd_packets": 500.0,
    "active_mean": 300.0, "active_std": 300.0, "idle_mean": 300.0, "idle_std": 300.0,
}


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _resolve_columns(df: pd.DataFrame) -> dict[str, str]:
    """Match the frame's actual columns to our feature names."""
    lookup = {_norm(c): c for c in df.columns}
    resolved: dict[str, str] = {}
    for feature, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in lookup:
                resolved[feature] = lookup[alias]
                break
    return resolved


def _label_column(df: pd.DataFrame) -> Optional[str]:
    for col in df.columns:
        if _norm(col) == "label":
            return col
    return None


def iter_csv_files(path: str) -> Iterator[str]:
    if os.path.isfile(path):
        yield path
        return
    files = sorted(glob.glob(os.path.join(path, "**", "*.csv"), recursive=True))
    if not files:
        raise FileNotFoundError(f"No CSV files found under {path}")
    yield from files


def load(path: str, max_rows_per_class: Optional[int] = None) -> tuple[np.ndarray, np.ndarray]:
    """Load CIC-IDS2017 into (X, y) with the classifier's feature order.

    Applies the preprocessing the report describes: duplicate removal, null and
    infinity handling, label folding, and per-feature normalisation.
    """
    frames: list[pd.DataFrame] = []

    for csv_path in iter_csv_files(path):
        df = pd.read_csv(csv_path, low_memory=False, skipinitialspace=True)
        label_col = _label_column(df)
        if label_col is None:
            logger.warning("Skipping %s: no Label column", os.path.basename(csv_path))
            continue

        resolved = _resolve_columns(df)
        missing = [f for f in FEATURES if f not in resolved]
        if missing:
            logger.warning(
                "%s: %d/%d features missing (e.g. %s); they will be zero-filled",
                os.path.basename(csv_path), len(missing), len(FEATURES), missing[:3],
            )

        out = pd.DataFrame(index=df.index)
        for feature in FEATURES:
            col = resolved.get(feature)
            out[feature] = pd.to_numeric(df[col], errors="coerce") if col else 0.0

        out["label"] = (
            df[label_col].astype(str).map(lambda v: _LABEL_MAP.get(_norm(v)))
        )
        frames.append(out)
        logger.info("Loaded %s (%d rows)", os.path.basename(csv_path), len(out))

    if not frames:
        raise ValueError(f"No usable CSV files under {path}")

    data = pd.concat(frames, ignore_index=True)
    before = len(data)

    # CICFlowMeter emits inf for rates on zero-duration flows.
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.dropna(subset=["label"])
    data[FEATURES] = data[FEATURES].fillna(0.0)
    data = data.drop_duplicates()
    logger.info("Preprocessing: %d rows -> %d after cleaning", before, len(data))

    if max_rows_per_class:
        data = (
            data.groupby("label", group_keys=False)
            .apply(lambda g: g.sample(min(len(g), max_rows_per_class), random_state=42))
            .reset_index(drop=True)
        )
        logger.info("Capped to %d rows per class -> %d rows", max_rows_per_class, len(data))

    scale = np.array([SCALES[f] for f in FEATURES], dtype=float)
    X = np.clip(data[FEATURES].to_numpy(dtype=float) / scale, 0.0, 1.0)
    y = data["label"].to_numpy()
    return X, y
