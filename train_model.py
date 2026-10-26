import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.utils import resample
import joblib
from url_features import extract_features

DATA_URL = "https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv"
df = pd.read_csv(DATA_URL)
df = df.dropna(subset=["url", "label"])
df["y"] = (df["label"].astype(str).str.lower() == "bad").astype(int)

bad = df[df.y == 1]
good = df[df.y == 0].sample(n=80_000, random_state=42)
bad_up = resample(bad, replace=True, n_samples=60_000, random_state=42)
df = pd.concat([good, bad_up]).sample(frac=1, random_state=42)

# Labels are domain-level: strip paths from half of good rows and graft real
# good-class paths onto half of bad rows, so path shape can't separate classes.
good_paths = []
for u in good["url"].astype(str):
    parts = u.split("/", 1)
    if len(parts) > 1 and parts[1]:
        good_paths.append(parts[1])

def mutate(row, i):
    u = str(row["url"])
    if row["y"] == 0 and i % 2 == 0:
        return u.split("/")[0]
    if row["y"] == 1 and i % 2 == 0 and good_paths:
        return u.rstrip("/") + "/" + good_paths[i % len(good_paths)]
    return u

df["url"] = [mutate(r, i) for i, (_, r) in enumerate(df.iterrows())]

X = [extract_features(u) for u in df["url"].astype(str)]
y = df["y"].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
clf = RandomForestClassifier(n_estimators=120, max_depth=24, n_jobs=-1, random_state=42)
clf.fit(X_train, y_train)

pred = clf.predict(X_test)
print("accuracy:", round(accuracy_score(y_test, pred), 4))
print(classification_report(y_test, pred, target_names=["legit", "malicious"]))

joblib.dump(clf, Path(__file__).parent / "rf_url_model.joblib")
print("model saved")