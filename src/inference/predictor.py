from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
import joblib
import numpy as np
import pandas as pd

from config import MODEL_PATH, TARGET_MAPPING
from src.inference.preprocessor import IDSPreprocessor
from src.features.feature_extractor import extract_features_from_flow
from src.network.flow_builder import Flow
from src.utils.logger import get_logger

logger = get_logger("IDSPredictor")


class IDSPredictor:
    """
    Inference engine for AI-Based Intrusion Detection System.
    Loads and reuses the trained machine learning pipeline.
    """

    _instance: Optional["IDSPredictor"] = None

    def __init__(self, model_path: Optional[Path | str] = None):
        path = Path(model_path or MODEL_PATH).resolve()

        if not path.is_file():
            raise FileNotFoundError(f"Model file not found at: {path}")

        logger.info(f"Loading trained IDS model from {path}...")
        self.model = joblib.load(path)

        if not hasattr(self.model, "feature_names_in_"):
            raise ValueError(
                "The loaded model does not expose feature_names_in_. "
                "Verify that the model was trained with named features."
            )

        self.feature_names = list(self.model.feature_names_in_)
        self.classes = list(getattr(self.model, "classes_", [0, 1]))
        self.preprocessor = IDSPreprocessor(expected_features=self.feature_names)

        logger.info(
            f"IDS Model loaded successfully: {len(self.feature_names)} features, "
            f"classes={self.classes}"
        )

    @classmethod
    def get_instance(cls, model_path: Optional[Path | str] = None) -> "IDSPredictor":
        """Singleton accessor to prevent reloading the model on every request."""
        if cls._instance is None:
            cls._instance = cls(model_path)
        return cls._instance

    def predict_dataframe(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Run intrusion detection predictions on an uploaded or batch DataFrame.
        Returns:
            (results_dataframe, summary_statistics)
        """
        if df.empty:
            raise ValueError("Input DataFrame is empty.")

        # Transform inputs into exact 74 features + presentation metadata
        X, meta = self.preprocessor.transform(df)

        # Generate model predictions
        raw_predictions = self.model.predict(X)
        pred_int = np.asarray(raw_predictions, dtype=int)

        # Calculate prediction probabilities / confidence
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X)
            # If binary classes [0, 1]
            if probabilities.shape[1] >= 2:
                attack_probs = probabilities[:, 1]
                confidences = probabilities.max(axis=1) * 100.0
            else:
                attack_probs = probabilities[:, 0]
                confidences = np.full(len(X), 100.0)
        else:
            attack_probs = np.full(len(X), np.nan)
            confidences = np.full(len(X), 100.0)

        # Build output results DataFrame
        results = pd.DataFrame(index=df.index)
        results["Flow_ID"] = np.arange(1, len(df) + 1)
        results["Timestamp"] = meta["Timestamp"]
        results["Protocol"] = meta["Protocol"]
        results["Source_IP"] = meta["Source_IP"]
        results["Source_Port"] = meta["Source_Port"]
        results["Destination_IP"] = meta["Destination_IP"]
        results["Destination_Port"] = meta["Destination_Port"]

        # Flow metrics from model inputs
        duration_sec = np.round(X["Flow_Duration"] / 1_000_000.0, 3)
        results["Duration"] = duration_sec
        results["Source_Bytes"] = X["Total_Length_of_Fwd_Packets"].fillna(0).astype(int)
        results["Download_Bytes"] = X["Total_Length_of_Bwd_Packets"].fillna(0).astype(int)
        results["Fwd_Packets"] = X["Total_Fwd_Packets"].fillna(0).astype(int)
        results["Bwd_Packets"] = X["Total_Backward_Packets"].fillna(0).astype(int)

        # Classification results
        results["Prediction_Value"] = pred_int
        results["Prediction"] = np.where(pred_int == 1, "ATTACK", "BENIGN")
        results["Confidence"] = np.round(confidences, 2)
        results["Attack_Probability"] = np.round(attack_probs, 4)

        # Attack category preservation / signature inference
        def resolve_attack_type(row):
            if row["Prediction_Value"] == 0:
                return "Normal Traffic"
            orig = str(meta.loc[row.name, "Original_Label"]).strip()
            if orig and orig.upper() not in {"BENIGN", "NORMAL", "0", ""}:
                return orig
            # Infer realistic attack family from flow characteristics
            dst_p = int(row.get("Destination_Port", 80))
            f_pkts_s = float(X.loc[row.name, "Flow_Packetss"]) if "Flow_Packetss" in X.columns else 0.0
            syn_cnt = float(X.loc[row.name, "SYN_Flag_Count"]) if "SYN_Flag_Count" in X.columns else 0.0
            
            if dst_p in (80, 443, 8080) and f_pkts_s > 500:
                return "DDoS"
            elif syn_cnt > 0 and float(X.loc[row.name, "ACK_Flag_Count"]) == 0:
                return "PortScan"
            elif dst_p in (21, 22):
                return "Brute Force"
            elif dst_p in (80, 8080):
                return "Web Attack"
            elif float(X.loc[row.name, "Active_Mean"]) > 1000000:
                return "Infiltration"
            return "Privilege Escalation"

        results["Attack_Type"] = [
            resolve_attack_type(row) for _, row in results.iterrows()
        ]

        # Calculate overall metrics
        total = len(results)
        attacks = int((pred_int == 1).sum())
        benign = int((pred_int == 0).sum())
        threat_percentage = round((attacks / total) * 100.0, 2) if total > 0 else 0.0
        avg_confidence = (
            round(float(confidences.mean()), 1)
            if not np.isnan(confidences).all()
            else None
        )

        # Attack category breakdown
        attack_records = results[results["Prediction_Value"] == 1]
        if not attack_records.empty:
            type_counts = attack_records["Attack_Type"].value_counts()
            attack_labels = type_counts.index.tolist()
            attack_counts = [int(v) for v in type_counts.tolist()]
        else:
            attack_labels = ["No Attacks Detected"]
            attack_counts = [0]

        summary = {
            "total": total,
            "attacks": attacks,
            "benign": benign,
            "threat_percentage": threat_percentage,
            "confidence": avg_confidence,
            "predictions_available": True,
            "attack_labels": attack_labels,
            "attack_counts": attack_counts,
        }

        return results, summary

    def predict_flow(self, flow: Flow) -> Dict[str, Any]:
        """Classify a single live or replayed network flow."""
        df_features = extract_features_from_flow(flow)
        raw_pred = int(self.model.predict(df_features)[0])

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(df_features)[0]
            confidence = float(probs[raw_pred]) * 100.0
            attack_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            confidence = 100.0
            attack_prob = float(raw_pred)

        prediction_label = "ATTACK" if raw_pred == 1 else "BENIGN"

        # Determine attack category
        if raw_pred == 1:
            dst_p = flow.forward_dst_port
            f_pkts_s = float(df_features["Flow_Packetss"].iloc[0])
            syn_cnt = float(df_features["SYN_Flag_Count"].iloc[0])
            if dst_p in (80, 443, 8080) and f_pkts_s > 500:
                attack_type = "DDoS"
            elif syn_cnt > 0 and float(df_features["ACK_Flag_Count"].iloc[0]) == 0:
                attack_type = "PortScan"
            elif dst_p in (21, 22):
                attack_type = "Brute Force"
            elif dst_p in (80, 8080):
                attack_type = "Web Attack"
            else:
                attack_type = "Privilege Escalation"
        else:
            attack_type = "Normal Traffic"

        duration = round(max(0.0, flow.last_timestamp - flow.first_timestamp), 3)

        return {
            "prediction": prediction_label,
            "prediction_value": raw_pred,
            "attack_type": attack_type,
            "confidence": round(confidence, 2),
            "attack_probability": round(attack_prob, 4),
            "src_ip": flow.forward_src_ip,
            "src_port": flow.forward_src_port,
            "dst_ip": flow.forward_dst_ip,
            "dst_port": flow.forward_dst_port,
            "protocol": flow.key[0],
            "duration": duration,
            "source_bytes": flow.forward_bytes,
            "download_bytes": flow.backward_bytes,
            "fwd_packets": flow.forward_packets,
            "bwd_packets": flow.backward_packets,
            "packets": len(flow.packets),
            "bytes": flow.forward_bytes + flow.backward_bytes,
            "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            "features": {k: round(float(v), 2) if isinstance(v, (int, float)) else str(v)
                         for k, v in df_features.iloc[0].to_dict().items()},
        }


def get_predictor() -> IDSPredictor:
    """Convenience function to get or initialize the singleton predictor."""
    return IDSPredictor.get_instance()
