"""
Machine Learning Training, Validation, and Model Persistence Module.

Trains a Random Forest classifier on extracted cryptographic features,
evaluates performance using confusion matrices and classification reports,
and provides serialization/deserialization routines using joblib.
"""

import os
from typing import Dict, Any, Tuple, List
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split

from src.features import extract_features_dataframe


def train_model(
    X: pd.DataFrame, y: pd.Series, test_size: float = 0.2, seed: int = 42
) -> Tuple[RandomForestClassifier, Dict[str, Any]]:
    """Train RandomForestClassifier on feature matrix X and target labels y."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=seed)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)
    report = classification_report(y_test, y_pred, output_dict=False)
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
        "classification_report_text": report,
        "classification_report_dict": report_dict,
        "feature_importances": feature_importances,
        "test_samples": len(y_test),
    }

    return clf, metrics


def save_model(model: RandomForestClassifier, filepath: str = "models/model.joblib") -> str:
    """Save trained model to disk using joblib."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    joblib.dump(model, filepath)
    return filepath


def load_model(filepath: str = "models/model.joblib") -> RandomForestClassifier:
    """Load trained model from disk using joblib."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Model file not found at '{filepath}'. Please train a model first.")
    return joblib.load(filepath)


def predict_sample(
    model: RandomForestClassifier, feature_dict: Dict[str, Any]
) -> Tuple[str, float, List[Tuple[str, float]]]:
    """Predict algorithm label, confidence, and top-3 probabilities for a single feature dictionary."""
    # Ensure feature DataFrame matches model input feature names and order
    if hasattr(model, "feature_names_in_"):
        expected_cols = list(model.feature_names_in_)
        sample_df = pd.DataFrame([[feature_dict.get(col, 0.0) for col in expected_cols]], columns=expected_cols)
    else:
        sample_df = pd.DataFrame([feature_dict])

    probs = model.predict_proba(sample_df)[0]
    classes = list(model.classes_)

    # Sort probabilities descending
    sorted_pairs = sorted(zip(classes, probs), key=lambda x: x[1], reverse=True)
    top_label, top_conf = sorted_pairs[0]
    top_3 = sorted_pairs[:3]

    return top_label, float(top_conf), top_3
