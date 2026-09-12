"""
Unit tests for model training, evaluation, and persistence pipeline.
"""

import os
import pytest
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from src.dataset_gen import generate_dataset
from src.features import extract_features_dataframe
from src.model import train_model, save_model, load_model, predict_sample


@pytest.fixture
def synthetic_features():
    df = generate_dataset(num_samples=600, seed=42)
    X, y = extract_features_dataframe(df)
    return X, y


def test_train_model(synthetic_features):
    X, y = synthetic_features
    model, metrics = train_model(X, y, test_size=0.2, seed=42)

    assert isinstance(model, RandomForestClassifier)
    assert metrics["accuracy"] > 0.65
    assert len(metrics["classes"]) == 6
    assert "confusion_matrix" in metrics
    assert "feature_importances" in metrics
    assert len(metrics["feature_importances"]) == X.shape[1]


def test_save_and_load_model(synthetic_features, tmp_path):
    X, y = synthetic_features
    model, _ = train_model(X, y, test_size=0.2, seed=42)

    model_path = str(tmp_path / "test_model.joblib")
    save_path = save_model(model, model_path, feature_names=list(X.columns))
    assert os.path.exists(save_path)

    loaded_model, feature_names = load_model(save_path)
    assert isinstance(loaded_model, RandomForestClassifier)
    assert loaded_model.classes_.tolist() == model.classes_.tolist()
    assert feature_names == list(X.columns)


def test_predict_sample(synthetic_features):
    X, y = synthetic_features
    model, _ = train_model(X, y, test_size=0.2, seed=42)

    sample_dict = X.iloc[0].to_dict()
    label, conf, top_3, exp_dict = predict_sample(model, sample_dict)

    assert isinstance(label, str)
    assert 0.0 <= conf <= 1.0
    assert len(top_3) <= 3
    assert top_3[0][0] == label
    assert top_3[0][1] == conf
    assert "verdict" in exp_dict
    assert "evidence_notes" in exp_dict
