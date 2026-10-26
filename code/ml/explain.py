from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
import shap


def explain(features: dict, limit: int = 8) -> dict:
    """Return the largest local SHAP contributions for the predicted class."""
    pre = joblib.load("models/preprocessor.joblib")
    model = joblib.load("models/risk_model.joblib")
    transformed = pre.transform(pd.DataFrame([features]))
    dense = transformed.toarray() if hasattr(transformed, "toarray") else np.asarray(transformed)
    predicted_index = int(np.argmax(model.predict_proba(dense)[0]))
    values = np.asarray(shap.TreeExplainer(model).shap_values(dense))
    if values.ndim == 3 and values.shape[0] == 1:
        contributions = values[0, :, predicted_index]
    elif values.ndim == 3:
        contributions = values[predicted_index, 0, :]
    elif values.ndim == 2:
        contributions = values[0]
    else:
        raise ValueError("Unsupported SHAP output shape")
    names = pre.get_feature_names_out()
    ranked = sorted(zip(names, contributions), key=lambda item: abs(float(item[1])), reverse=True)[:limit]
    return {
        "available": True,
        "predicted_priority": str(model.classes_[predicted_index]),
        "factors": [
            {"feature": str(name).replace("num__", "").replace("cat__", ""),
             "contribution": round(float(value), 5),
             "direction": "increases" if float(value) >= 0 else "decreases"}
            for name, value in ranked
        ],
    }
