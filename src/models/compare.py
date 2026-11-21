from typing import Dict, Any
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.utils.metrics import compute_ids_metrics


def compare_baseline_models(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
) -> Dict[str, Dict[str, Any]]:
    """Compare performance across baseline classifiers."""
    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=500, random_state=42, class_weight="balanced")),
        ]),
        "Random Forest": Pipeline([
            ("model", RandomForestClassifier(n_estimators=50, random_state=42, class_weight="balanced", n_jobs=-1)),
        ]),
    }

    results = {}
    for name, pipeline in models.items():
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_val)
        results[name] = compute_ids_metrics(y_val.values, y_pred)

    return results
