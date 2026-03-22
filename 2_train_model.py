"""
NIDS Model Training
===================
Trains a Random Forest classifier on the generated NIDS dataset.
Outputs:
  models/rf_nids_model.pkl    — trained model
  models/scaler.pkl           — StandardScaler
  models/feature_names.pkl    — feature list
  reports/training_report.txt — metrics, confusion matrix
  reports/feature_importance.png
  reports/confusion_matrix.png
  reports/roc_curve.png
"""

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (classification_report, confusion_matrix,
                              roc_auc_score, roc_curve, accuracy_score,
                              precision_score, recall_score, f1_score)
import joblib, json, textwrap

np.random.seed(42)

MODEL_DIR  = Path("models");  MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR = Path("reports"); REPORT_DIR.mkdir(exist_ok=True)

# ─── 1. Load Data ──────────────────────────────────────────────────────────
df = pd.read_csv("data/nids_dataset.csv")
FEATURES = [c for c in df.columns if c != "label"]
X = df[FEATURES].values
y = df["label"].values

print(f"Dataset: {len(df)} samples | {len(FEATURES)} features")
print(f"Class balance: Normal={sum(y==0)} | Suspicious={sum(y==1)}\n")

# ─── 2. Train / Test Split ─────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y)

# ─── 3. Scale Features ─────────────────────────────────────────────────────
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

# ─── 4. Train Random Forest ────────────────────────────────────────────────
rf = RandomForestClassifier(
    n_estimators   = 100,
    max_depth      = 15,
    min_samples_split = 4,
    min_samples_leaf  = 2,
    max_features   = "sqrt",
    class_weight   = "balanced",
    random_state   = 42,
    n_jobs         = -1,
)
rf.fit(X_train_s, y_train)
print("✓ Random Forest trained")

# ─── 5. Evaluation ─────────────────────────────────────────────────────────
y_pred     = rf.predict(X_test_s)
y_prob     = rf.predict_proba(X_test_s)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)
auc  = roc_auc_score(y_test, y_prob)

print(f"\n{'='*50}")
print(f"  Accuracy  : {acc*100:.2f}%")
print(f"  Precision : {prec*100:.2f}%")
print(f"  Recall    : {rec*100:.2f}%")
print(f"  F1 Score  : {f1*100:.2f}%")
print(f"  ROC-AUC   : {auc*100:.2f}%")
print(f"{'='*50}\n")

# ─── 6. Cross Validation ───────────────────────────────────────────────────
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(rf, scaler.transform(X), y, cv=cv, scoring='f1')
print(f"5-Fold CV F1: {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%\n")

# ─── 7. Save Report ────────────────────────────────────────────────────────
cm = confusion_matrix(y_test, y_pred)
report_txt = textwrap.dedent(f"""
NIDS Random Forest — Training Report
=====================================
Dataset          : {len(df)} samples
Train / Test     : {len(X_train)} / {len(X_test)}
Features         : {len(FEATURES)}

Model Parameters
----------------
n_estimators     : 100
max_depth        : 15
max_features     : sqrt
class_weight     : balanced

Performance Metrics
-------------------
Accuracy         : {acc*100:.2f}%
Precision        : {prec*100:.2f}%
Recall           : {rec*100:.2f}%
F1 Score         : {f1*100:.2f}%
ROC-AUC          : {auc*100:.2f}%
5-Fold CV F1     : {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%

Confusion Matrix
----------------
              Predicted
              Normal  Susp
Actual Normal  {cm[0,0]:5d}  {cm[0,1]:5d}
       Susp    {cm[1,0]:5d}  {cm[1,1]:5d}

Classification Report
---------------------
{classification_report(y_test, y_pred, target_names=['Normal','Suspicious'])}
""")
with open(REPORT_DIR / "training_report.txt", "w") as f:
    f.write(report_txt)
print(report_txt)

# ─── 8. Feature Importance Plot ────────────────────────────────────────────
fi = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=True)

fig, ax = plt.subplots(figsize=(9, 5))
fig.patch.set_facecolor('#020b06')
ax.set_facecolor('#041209')
colors = ['#00ff6a' if v > fi.median() else '#00a344' for v in fi.values]
ax.barh(fi.index, fi.values, color=colors, edgecolor='#0d3320', linewidth=0.5)
for spine in ax.spines.values(): spine.set_edgecolor('#0d3320')
ax.tick_params(colors='#b0ffcc', labelsize=9)
ax.set_xlabel('Importance Score', color='#3a7a50', fontsize=9)
ax.set_title('Random Forest — Feature Importances', color='#00ff6a',
             fontsize=12, fontfamily='monospace', pad=12)
ax.xaxis.label.set_color('#3a7a50')
plt.tight_layout()
plt.savefig(REPORT_DIR / "feature_importance.png", dpi=150, bbox_inches='tight',
            facecolor='#020b06')
plt.close()
print("✓ Saved feature_importance.png")

# ─── 9. Confusion Matrix Plot ──────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(5, 4))
fig.patch.set_facecolor('#020b06')
ax.set_facecolor('#041209')
sns.heatmap(cm, annot=True, fmt='d', cmap='Greens',
            xticklabels=['Normal','Suspicious'],
            yticklabels=['Normal','Suspicious'],
            linewidths=0.5, linecolor='#0d3320', ax=ax,
            annot_kws={'color':'white','size':14,'weight':'bold'})
ax.set_title('Confusion Matrix', color='#00ff6a', fontsize=12,
             fontfamily='monospace', pad=10)
ax.set_xlabel('Predicted', color='#3a7a50'); ax.set_ylabel('Actual', color='#3a7a50')
ax.tick_params(colors='#b0ffcc')
plt.tight_layout()
plt.savefig(REPORT_DIR / "confusion_matrix.png", dpi=150, bbox_inches='tight',
            facecolor='#020b06')
plt.close()
print("✓ Saved confusion_matrix.png")

# ─── 10. ROC Curve ─────────────────────────────────────────────────────────
fpr, tpr, _ = roc_curve(y_test, y_prob)
fig, ax = plt.subplots(figsize=(6, 5))
fig.patch.set_facecolor('#020b06')
ax.set_facecolor('#041209')
ax.plot(fpr, tpr, color='#00ff6a', lw=2, label=f'ROC (AUC = {auc:.4f})')
ax.plot([0,1],[0,1], color='#0d3320', lw=1, linestyle='--')
ax.fill_between(fpr, tpr, alpha=0.08, color='#00ff6a')
for spine in ax.spines.values(): spine.set_edgecolor('#0d3320')
ax.tick_params(colors='#b0ffcc', labelsize=9)
ax.set_xlabel('False Positive Rate', color='#3a7a50')
ax.set_ylabel('True Positive Rate',  color='#3a7a50')
ax.set_title('ROC Curve — Random Forest NIDS', color='#00ff6a',
             fontsize=12, fontfamily='monospace')
ax.legend(facecolor='#041209', edgecolor='#0d3320', labelcolor='#b0ffcc', fontsize=9)
plt.tight_layout()
plt.savefig(REPORT_DIR / "roc_curve.png", dpi=150, bbox_inches='tight',
            facecolor='#020b06')
plt.close()
print("✓ Saved roc_curve.png")

# ─── 11. Save Model ────────────────────────────────────────────────────────
joblib.dump(rf,       MODEL_DIR / "rf_nids_model.pkl")
joblib.dump(scaler,   MODEL_DIR / "scaler.pkl")
joblib.dump(FEATURES, MODEL_DIR / "feature_names.pkl")

meta = {"accuracy": round(acc,4), "precision": round(prec,4),
        "recall": round(rec,4), "f1": round(f1,4),
        "roc_auc": round(auc,4), "n_features": len(FEATURES),
        "n_estimators": 100, "features": FEATURES}
with open(MODEL_DIR / "model_meta.json","w") as f:
    json.dump(meta, f, indent=2)

print(f"\n✓ Model saved → models/rf_nids_model.pkl")
print(f"✓ Scaler saved → models/scaler.pkl")
print(f"✓ Report saved → reports/training_report.txt")