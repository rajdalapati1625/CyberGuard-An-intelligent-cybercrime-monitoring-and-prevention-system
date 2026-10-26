import pandas as pd
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

DATA_URL = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"
df = pd.read_csv(DATA_URL, sep="\t", header=None, names=["label", "text"])
df = df.dropna(subset=["label", "text"])
df["y"] = (df["label"].astype(str).str.lower() == "spam").astype(int)
print("rows:", len(df), "| spam share:", round(df.y.mean(), 3))

X_train, X_test, y_train, y_test = train_test_split(
    df["text"].astype(str), df["y"], test_size=0.2, random_state=42, stratify=df["y"]
)

pipe = Pipeline([
    ("tfidf", TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2), min_df=2)),
    ("clf", MultinomialNB()),
])
pipe.fit(X_train, y_train)

pred = pipe.predict(X_test)
print("accuracy:", round(accuracy_score(y_test, pred), 4))
print(classification_report(y_test, pred, target_names=["ham", "spam"]))

joblib.dump(pipe, Path(__file__).parent / "spam_model.joblib")
print("model saved")