import re
from typing import Any
import numpy as np
import pandas as pd


def clean_column_name(column: str) -> str:
    """
    Standardize raw column names matching the training pipeline:
    - Strips leading/trailing spaces
    - Replaces spaces with underscores
    - Removes characters other than alphanumeric and underscores
    - Collapses consecutive underscores
    """
    col = str(column).strip()
    col = col.replace(" ", "_")
    col = re.sub(r"[^A-Za-z0-9_]", "", col)
    col = re.sub(r"_+", "_", col)
    return col


def clean_numeric_features(df: pd.DataFrame, fill_value: float = 0.0) -> pd.DataFrame:
    """
    Safely convert all columns to float, replacing infinity and NaN with fill_value.
    """
    cleaned = df.copy()

    for column in cleaned.columns:
        cleaned[column] = pd.to_numeric(cleaned[column], errors="coerce")

    cleaned = cleaned.replace([np.inf, -np.inf], np.nan)
    cleaned = cleaned.fillna(fill_value)

    return cleaned


def standardize_label(label: Any) -> int:
    """
    Convert arbitrary string or integer label to binary intrusion target:
    0 = BENIGN, 1 = ATTACK.
    """
    if pd.isna(label):
        return 0

    text = str(label).strip().upper()
    if text in {"0", "BENIGN", "NORMAL", "FALSE"}:
        return 0
    return 1
