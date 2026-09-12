"""
Machine Learning Training, Validation, and Model Persistence Module.

Trains a Random Forest classifier on extracted cryptographic features,
evaluates performance using confusion matrices and classification reports,
and provides serialization/deserialization routines using joblib.
"""

import os
from typing import Dict, Any, Tuple, List, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split

from src.explainability import ForensicExplainer


def train_model(
    X: pd.DataFrame, y: pd.Series, test_size: float = 0.2, seed: int = 42
) -> Tuple[RandomForestClassifier, Dict[str, Any]]:
    """Train RandomForestClassifier on feature matrix X and target labels y."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=150, max_depth=18, random_state=seed)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)
    report_text = classification_report(y_test, y_pred, output_dict=False)
    report_dict = classification_report(y_test, y_pred, output_dict=True)

    feature_importances = dict(
        sorted(
            zip(X.columns, clf.feature_importances_),
            key=lambda item: item[1],
            reverse=True,
        )
    )

    metrics = {
        "accuracy": acc,
        "confusion_matrix": cm.tolist(),
        "classes": list(clf.classes_),
        "classification_report_text": report_text,
        "classification_report_dict": report_dict,
        "feature_importances": feature_importances,
        "feature_names": list(X.columns),
        "test_samples": len(y_test),
    }

    return clf, metrics


def save_model(
    model: RandomForestClassifier, filepath: str = "models/model.joblib", feature_names: List[str] = None
) -> str:
    """Save trained model and strict feature order metadata to disk using joblib."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if feature_names is None and hasattr(model, "feature_names_in_"):
        feature_names = list(model.feature_names_in_)

    payload = {
        "model": model,
        "feature_names": feature_names,
        "classes": list(model.classes_),
    }
    joblib.dump(payload, filepath)
    return filepath


def load_model(filepath: str = "models/model.joblib") -> Tuple[RandomForestClassifier, List[str]]:
    """Load trained model payload from disk using joblib, returning (model, feature_names)."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Model file not found at '{filepath}'. Please train a model first.")
    
    data = joblib.load(filepath)
    if isinstance(data, dict) and "model" in data:
        return data["model"], data.get("feature_names", [])
    elif isinstance(data, RandomForestClassifier):
        feature_names = list(data.feature_names_in_) if hasattr(data, "feature_names_in_") else []
        return data, feature_names
    else:
        raise ValueError("Invalid model file format.")


def predict_sample(
    model_obj: Union[RandomForestClassifier, Tuple[RandomForestClassifier, List[str]]],
    feature_dict: Dict[str, Any],
    feature_names: List[str] = None,
) -> Tuple[str, float, List[Tuple[str, float]], Dict[str, Any]]:
    """Predict algorithm label, confidence, top-3 probabilities, and forensic explainability breakdown."""
    if isinstance(model_obj, tuple):
        model, stored_feature_names = model_obj
        if feature_names is None:
            feature_names = stored_feature_names
    else:
        model = model_obj

    if feature_names is None or len(feature_names) == 0:
        if hasattr(model, "feature_names_in_"):
            feature_names = list(model.feature_names_in_)

    # Enforce strict feature ordering matching training matrix
    if feature_names:
        row = [feature_dict.get(col, 0.0) for col in feature_names]
        sample_df = pd.DataFrame([row], columns=feature_names)
    else:
        sample_df = pd.DataFrame([feature_dict])

    probs = model.predict_proba(sample_df)[0]
    classes = list(model.classes_)

    # Sort probabilities descending
    sorted_pairs = sorted(zip(classes, probs), key=lambda x: x[1], reverse=True)
    top_label, top_conf = sorted_pairs[0]
    top_3 = sorted_pairs[:3]

    explanation = ForensicExplainer.explain(top_label, float(top_conf), top_3, feature_dict)

    return top_label, float(top_conf), top_3, explanation
