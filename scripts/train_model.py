from pathlib import Path
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
from config import MODEL_PATH, METADATA_PATH, PROCESSED_DATA_DIR, FEATURE_CONFIG_PATH


def train_ids_model(
    train_path: Path = PROCESSED_DATA_DIR / "train.csv",
    output_model_path: Path = MODEL_PATH,
    n_estimators: int = 100,
    sample_size: int = 50000,
):
    print("=" * 70)
    print("TRAINING AI-BASED INTRUSION DETECTION SYSTEM MODEL")
    print("=" * 70)

    if not train_path.is_file():
        raise FileNotFoundError(f"Training dataset not found: {train_path}")

    with open(FEATURE_CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
    feature_names = config["features"]

    print(f"Loading {sample_size:,} training rows from {train_path}...")
    df = pd.read_csv(train_path, nrows=sample_size, low_memory=False)

    X = df[feature_names].fillna(0.0)
    y = df["Attack"].astype(int)

    print(f"Features: {X.shape[1]}, Samples: {len(X):,}")
    print(f"Class distribution: Benign={(y == 0).sum():,}, Attack={(y == 1).sum():,}")

    pipeline = Pipeline([
        ("model", RandomForestClassifier(
            n_estimators=n_estimators,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ))
    ])

    print("\nFitting Random Forest model...")
    pipeline.fit(X, y)

    output_model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, output_model_path)
    print(f"Model saved successfully to: {output_model_path}")
    return pipeline


if __name__ == "__main__":
    train_ids_model()
