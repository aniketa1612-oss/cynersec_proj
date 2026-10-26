import json
from pathlib import Path
import matplotlib.pyplot as plt
data = json.loads(Path("reports/model_evaluation.json").read_text())
cm = data["confusion_matrix"]
fig, ax = plt.subplots()
image = ax.imshow(cm, cmap="Blues")
ax.set(xticks=range(len(data["classes"])), yticks=range(len(data["classes"])), xticklabels=data["classes"],
       yticklabels=data["classes"], xlabel="Predicted", ylabel="Actual", title="Risk priority confusion matrix")
for i, row in enumerate(cm):
    for j, value in enumerate(row):
        ax.text(j, i, value, ha="center", va="center")
fig.colorbar(image)
fig.tight_layout()
fig.savefig("reports/confusion_matrix.png", dpi=180)
print("Saved reports/confusion_matrix.png")
