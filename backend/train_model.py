import pandas as pd

df = pd.read_csv(r"D:\Mini project\backend\malicious_phish.csv")
df = df.drop_duplicates()
print(df.duplicated().sum())

import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from features import extract_features

feature_list = []

for url in df["url"]:
    feature_list.append(extract_features(url))

X = pd.DataFrame(feature_list)
y = df["type"]
print(X.head())

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
    #keeps the same percentage of each class in both the training and testing sets.
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("Accuracy:", accuracy)
print(classification_report(y_test, y_pred))
