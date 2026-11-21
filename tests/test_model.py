import pytest
import numpy as np
import pandas as pd
import joblib

from config import MODEL_PATH, FEATURE_CONFIG_PATH
from src.inference.predictor import get_predictor


def test_model_file_exists():
    assert MODEL_PATH.is_file(), f"Trained model not found at {MODEL_PATH}"


def test_model_loading_and_attributes():
    model = joblib.load(MODEL_PATH)
    assert hasattr(model, "predict"), "Model does not have a predict method."
    assert hasattr(model, "predict_proba"), "Model does not have a predict_proba method."
    assert hasattr(model, "feature_names_in_"), "Model missing feature_names_in_."
    assert len(model.feature_names_in_) == 74, f"Expected 74 features, got {len(model.feature_names_in_)}"
    assert list(model.classes_) == [0, 1], f"Expected classes [0, 1], got {model.classes_}"


def test_predictor_singleton():
    pred1 = get_predictor()
    pred2 = get_predictor()
    assert pred1 is pred2, "get_predictor() should return the same singleton instance."


def test_model_prediction_on_synthetic_records():
    predictor = get_predictor()
    features = predictor.feature_names

    # All-zero benign flow
    zero_df = pd.DataFrame([np.zeros(len(features))], columns=features)
    pred_val = predictor.model.predict(zero_df)[0]
    probs = predictor.model.predict_proba(zero_df)[0]

    assert pred_val in [0, 1]
    assert len(probs) == 2
    assert 0.0 <= probs[0] <= 1.0
    assert 0.0 <= probs[1] <= 1.0
    assert np.isclose(probs.sum(), 1.0)
