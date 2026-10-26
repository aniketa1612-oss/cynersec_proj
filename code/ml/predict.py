import joblib, pandas as pd
def predict(features: dict):
    pre = joblib.load("models/preprocessor.joblib")
    model = joblib.load("models/risk_model.joblib")
    probs = model.predict_proba(pre.transform(pd.DataFrame([features])))[0]
    i = probs.argmax()
    return {"priority": model.classes_[i], "confidence": float(probs[i]), "probabilities": dict(zip(model.classes_, map(float, probs)))}

