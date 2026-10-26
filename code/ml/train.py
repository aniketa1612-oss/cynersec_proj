from pathlib import Path
import json, os, joblib, pandas as pd
import mlflow
import mlflow.sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from ml.features import NUMERIC, CATEGORICAL
data = Path("data/processed/security_dataset.csv")
data = data if data.exists() else Path("data/sample/security_dataset.csv")
df = pd.read_csv(data)
X, y = df[NUMERIC+CATEGORICAL], df.risk_priority
pre = ColumnTransformer([
 ("num", Pipeline([("fill", SimpleImputer(strategy="median")), ("scale", StandardScaler())]), NUMERIC),
 ("cat", Pipeline([("fill", SimpleImputer(strategy="most_frequent")), ("onehot", OneHotEncoder(handle_unknown="ignore"))]), CATEGORICAL)])
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.25, random_state=42, stratify=y if y.value_counts().min() > 1 else None)
model = RandomForestClassifier(n_estimators=250, class_weight="balanced", random_state=42)
mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "file:./mlruns"))
mlflow.set_experiment("adaptive-risk-prioritization")
with mlflow.start_run(run_name="random-forest"):
    mlflow.log_params({"model":"RandomForestClassifier","n_estimators":250,"class_weight":"balanced","rows":len(df)})
    mlflow.log_input(mlflow.data.from_pandas(df, source=str(data)), context="training")
    Xt = pre.fit_transform(Xtr)
    model.fit(Xt, ytr)
    pred = model.predict(pre.transform(Xte))
    Path("models").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)
    joblib.dump(model, "models/risk_model.joblib")
    joblib.dump(pre, "models/preprocessor.joblib")
    metrics = {"accuracy": accuracy_score(yte, pred), "macro_f1": f1_score(yte, pred, average="macro"),
     "confusion_matrix": confusion_matrix(yte, pred, labels=model.classes_).tolist(), "classes": model.classes_.tolist(),
     "classification_report": classification_report(yte, pred, zero_division=0, output_dict=True)}
    Path("reports/model_evaluation.json").write_text(json.dumps(metrics, indent=2))
    mlflow.log_metrics({"accuracy":metrics["accuracy"],"macro_f1":metrics["macro_f1"]})
    mlflow.log_artifact("reports/model_evaluation.json")
    mlflow.sklearn.log_model(model, "risk-model")
print(json.dumps({"dataset": str(data), "rows": len(df), "accuracy": metrics["accuracy"], "macro_f1": metrics["macro_f1"]}, indent=2))

