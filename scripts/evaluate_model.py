from pathlib import Path
import sys
import pandas as pd
import numpy as np

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import MODEL_PATH, RAW_DATA_DIR, PROCESSED_DATA_DIR
from src.inference.predictor import get_predictor
from src.utils.metrics import compute_ids_metrics


def evaluate_dataset(file_path: Path, nrows: int = 20000):
    print("=" * 70)
    print("AI-BASED INTRUSION DETECTION SYSTEM - MODEL EVALUATION")
    print("=" * 70)

    if not file_path.is_file():
        raise FileNotFoundError(f"Evaluation file not found: {file_path}")

    print(f"Dataset path : {file_path}")
    print(f"Sample limit : {nrows:,} rows")

    predictor = get_predictor()

    print("\nLoading dataset sample...")
    df = pd.read_csv(file_path, nrows=nrows, low_memory=False)
    df.columns = df.columns.astype(str).str.strip()

    # Determine ground truth label
    target_col = None
    for candidate in ["Attack", "Label", "label", "class"]:
        if candidate in df.columns:
            target_col = candidate
            break

    if not target_col:
        raise ValueError(
            f"No ground truth label column found in dataset. Columns: {list(df.columns[:10])}"
        )

    if target_col == "Attack":
        y_true = df["Attack"].astype(int).values
    else:
        y_true = df[target_col].astype(str).str.strip().str.upper().ne("BENIGN").astype(int).values

    print(f"Ground truth distribution: Benign={(y_true == 0).sum():,}, Attacks={(y_true == 1).sum():,}")

    print("\nRunning inference through IDSPredictor pipeline...")
    results_df, summary = predictor.predict_dataframe(df)
    y_pred = results_df["Prediction_Value"].values

    metrics = compute_ids_metrics(y_true, y_pred)

    print("\n" + "=" * 70)
    print("EVALUATION METRICS REPORT")
    print("=" * 70)
    print(f"Total Evaluated Flows : {metrics['total_samples']:,}")
    print(f"Accuracy Score        : {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision Score       : {metrics['precision'] * 100:.2f}%")
    print(f"Recall (Detection)    : {metrics['recall'] * 100:.2f}%")
    print(f"F1-Score              : {metrics['f1_score'] * 100:.2f}%")
    print(f"False Positive Rate   : {metrics['false_positive_rate'] * 100:.2f}%")
    print(f"False Negative Rate   : {metrics['false_negative_rate'] * 100:.2f}%")
    print("\nConfusion Matrix:")
    cm = metrics["confusion_matrix"]
    print(f"  True Negatives  (Benign correctly identified)  : {cm['true_negative']:,}")
    print(f"  False Positives (Benign misclassified as attack): {cm['false_positive']:,}")
    print(f"  False Negatives (Attacks missed)                : {cm['false_negative']:,}")
    print(f"  True Positives  (Attacks correctly detected)    : {cm['true_positive']:,}")
    print("=" * 70)

    return metrics


if __name__ == "__main__":
    # Prefer validation or test CSV if available, otherwise raw CICIDS2017
    test_csv = PROCESSED_DATA_DIR / "test.csv"
    raw_csv = RAW_DATA_DIR / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

    eval_path = test_csv if test_csv.is_file() else raw_csv
    evaluate_dataset(eval_path, nrows=10000)
