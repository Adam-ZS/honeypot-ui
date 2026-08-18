from __future__ import annotations
import os
import pickle
import numpy as np
from typing import List, Dict, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from app.core.config import get_settings

settings = get_settings()

ATTACK_LABELS = ["benign", "reconnaissance", "exploitation", "exfiltration"]


class FeatureExtractor:
    CICIDS_FEATURES = [
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

    @staticmethod
    def extract_from_session(session_data: Dict) -> np.ndarray:
        values = [
            session_data.get(feat, 0.0)
            for feat in FeatureExtractor.CICIDS_FEATURES
        ]
        return FeatureExtractor._normalise(values)

    #: Rough upper bound per feature, used to map raw observations into the
    #: [0, 1] range the model is trained on. Without this, raw magnitudes
    #: (durations in seconds, byte counts) were fed to a model fitted on
    #: clipped [0, 1] data, so predictions were effectively arbitrary.
    FEATURE_SCALES = {
        "flow_duration": 600.0,
        "total_fwd_packets": 500.0,
        "total_bwd_packets": 500.0,
        "fwd_packet_length_mean": 1500.0,
        "fwd_packet_length_std": 1500.0,
        "bwd_packet_length_mean": 1500.0,
        "bwd_packet_length_std": 1500.0,
        "flow_bytes_per_second": 100000.0,
        "flow_packets_per_second": 500.0,
        "fwd_header_length": 500.0,
        "bwd_header_length": 500.0,
        "fwd_packets_per_second": 200.0,
        "bwd_packets_per_second": 200.0,
        "min_packet_length": 1500.0,
        "max_packet_length": 1500.0,
        "packet_length_mean": 1500.0,
        "packet_length_std": 1500.0,
        "packet_length_variance": 1000000.0,
        "fin_flag_count": 50.0,
        "syn_flag_count": 50.0,
        "rst_flag_count": 50.0,
        "psh_flag_count": 100.0,
        "ack_flag_count": 200.0,
        "urg_flag_count": 20.0,
        "down_up_ratio": 10.0,
        "average_packet_size": 1500.0,
        "fwd_segment_size_mean": 1500.0,
        "bwd_segment_size_mean": 1500.0,
        "fwd_bytes_per_bulk": 10000.0,
        "fwd_bulk_rate": 10000.0,
        "subflow_fwd_packets": 500.0,
        "subflow_bwd_packets": 500.0,
        "active_mean": 300.0,
        "active_std": 300.0,
        "idle_mean": 300.0,
        "idle_std": 300.0,
    }

    @classmethod
    def _normalise(cls, values: List[float]) -> np.ndarray:
        scaled = [
            min(max(float(value) / cls.FEATURE_SCALES[name], 0.0), 1.0)
            for name, value in zip(cls.CICIDS_FEATURES, values)
        ]
        return np.array(scaled).reshape(1, -1)

    @staticmethod
    def extract_from_raw(
        packets: List[Dict],
        commands: List[str],
        duration: float,
    ) -> np.ndarray:
        total_fwd = sum(1 for p in packets if p.get("direction") == "outbound")
        total_bwd = len(packets) - total_fwd
        fwd_lengths = [len(p.get("payload", "")) for p in packets if p.get("direction") == "outbound"]
        bwd_lengths = [len(p.get("payload", "")) for p in packets if p.get("direction") == "inbound"]
        all_lengths = [len(p.get("payload", "")) for p in packets]

        syn_count = sum(1 for p in packets if p.get("flags", {}).get("syn", False))
        fin_count = sum(1 for p in packets if p.get("flags", {}).get("fin", False))
        rst_count = sum(1 for p in packets if p.get("flags", {}).get("rst", False))
        psh_count = sum(1 for p in packets if p.get("flags", {}).get("psh", False))
        ack_count = sum(1 for p in packets if p.get("flags", {}).get("ack", False))
        urg_count = sum(1 for p in packets if p.get("flags", {}).get("urg", False))

        command_entropy = FeatureExtractor._shannon_entropy(" ".join(commands)) if commands else 0
        unique_commands = len(set(commands)) if commands else 0

        features = [
            duration,
            total_fwd, total_bwd,
            np.mean(fwd_lengths) if fwd_lengths else 0,
            np.std(fwd_lengths) if fwd_lengths else 0,
            np.mean(bwd_lengths) if bwd_lengths else 0,
            np.std(bwd_lengths) if bwd_lengths else 0,
            sum(all_lengths) / max(duration, 0.001),
            len(packets) / max(duration, 0.001),
            sum(1 for p in packets if p.get("direction") == "outbound" and p.get("header_size", 0)),
            sum(1 for p in packets if p.get("direction") == "inbound" and p.get("header_size", 0)),
            total_fwd / max(duration, 0.001),
            total_bwd / max(duration, 0.001),
            min(all_lengths) if all_lengths else 0,
            max(all_lengths) if all_lengths else 0,
            np.mean(all_lengths) if all_lengths else 0,
            np.std(all_lengths) if all_lengths else 0,
            np.var(all_lengths) if all_lengths else 0,
            fin_count, syn_count, rst_count, psh_count, ack_count, urg_count,
            total_fwd / max(total_bwd, 1),
            np.mean(all_lengths) if all_lengths else 0,
            np.mean(fwd_lengths) if fwd_lengths else 0,
            np.mean(bwd_lengths) if bwd_lengths else 0,
            0, 0,
            total_fwd, total_bwd,
            0, 0, 0, 0,
            command_entropy, unique_commands,
        ]
        return FeatureExtractor._normalise(
            features[: len(FeatureExtractor.CICIDS_FEATURES)]
        )

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * np.log2(count / length) for count in freq.values())


class AttackClassifier:
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.feature_extractor = FeatureExtractor()
        self.model_source = "unloaded"
        self._loaded = False

    def _ensure_loaded(self):
        if self._loaded:
            return
        model_path = settings.MODEL_PATH_RF
        if os.path.exists(model_path):
            # pickle executes arbitrary code on load, so only ever read the
            # operator-controlled path from configuration, never user input.
            with open(model_path, "rb") as f:
                data = pickle.load(f)
            self.model = data["model"]
            self.label_encoder = data["label_encoder"]
            self.model_source = data.get("source", "pretrained")
        else:
            self._train_default_model()
            self.model_source = "synthetic"
        self._loaded = True

    def _train_default_model(self):
        """Fit a bootstrap model on synthetic traffic.

        This exists so a fresh deployment has *something* to classify with;
        it is not trained on real capture data and its confidence scores are
        not calibrated. Responses are tagged ``model_source: synthetic``
        so the UI never presents them as ground truth. Replace by training on
        a labelled corpus (e.g. CIC-IDS2017) and dropping the artefact at
        MODEL_PATH_RF.
        """
        np.random.seed(42)
        n_samples = 2000
        n_features = len(FeatureExtractor.CICIDS_FEATURES)

        X_benign = np.random.normal(0.5, 0.3, (n_samples, n_features)).clip(0, 1)
        X_recon = np.random.normal(0.3, 0.2, (n_samples // 2, n_features)).clip(0, 1)
        X_recon[:, 19] = np.random.normal(0.8, 0.1, n_samples // 2).clip(0, 1)
        X_exploit = np.random.normal(0.7, 0.2, (n_samples // 2, n_features)).clip(0, 1)
        X_exploit[:, 21] = np.random.normal(0.9, 0.1, n_samples // 2).clip(0, 1)
        X_exfil = np.random.normal(0.6, 0.25, (n_samples // 2, n_features)).clip(0, 1)
        X_exfil[:, 7] = np.random.normal(0.9, 0.1, n_samples // 2).clip(0, 1)

        X = np.vstack([X_benign, X_recon, X_exploit, X_exfil])
        y = (["benign"] * n_samples +
             ["reconnaissance"] * (n_samples // 2) +
             ["exploitation"] * (n_samples // 2) +
             ["exfiltration"] * (n_samples // 2))

        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=1,
        )
        self.model.fit(X, y_encoded)

        os.makedirs(os.path.dirname(settings.MODEL_PATH_RF) or ".", exist_ok=True)
        with open(settings.MODEL_PATH_RF, "wb") as f:
            pickle.dump(
                {
                    "model": self.model,
                    "label_encoder": self.label_encoder,
                    "source": "synthetic",
                },
                f,
            )

    def _predict(self, features: np.ndarray) -> Dict:
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        return {
            "category": str(self.label_encoder.inverse_transform([prediction])[0]),
            "confidence": float(max(probabilities)),
            "probabilities": {
                str(label): float(prob)
                for label, prob in zip(
                    self.label_encoder.classes_, probabilities
                )
            },
            # Consumers must be able to tell a bootstrap verdict from one
            # produced by a model trained on real labelled traffic.
            "model_source": self.model_source,
        }

    def classify(self, session_data: Dict) -> Dict:
        self._ensure_loaded()
        return self._predict(
            self.feature_extractor.extract_from_session(session_data)
        )

    def classify_raw(
        self, packets: List[Dict], commands: List[str], duration: float
    ) -> Dict:
        self._ensure_loaded()
        return self._predict(
            self.feature_extractor.extract_from_raw(packets, commands, duration)
        )


classifier = AttackClassifier()
