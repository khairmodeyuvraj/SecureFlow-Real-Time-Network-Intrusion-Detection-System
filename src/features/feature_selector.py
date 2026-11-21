from typing import List
import pandas as pd


def remove_constant_features(df: pd.DataFrame, threshold: float = 0.0) -> List[str]:
    """Identify features with zero or near-zero variance."""
    constant_cols = [col for col in df.columns if df[col].nunique(dropna=False) <= 1]
    return constant_cols


def select_top_features_by_importance(
    feature_names: List[str],
    importances: List[float],
    top_n: int = 20,
) -> List[str]:
    """Rank and select top N features based on model feature importances."""
    ranked = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    return [name for name, _ in ranked[:top_n]]
