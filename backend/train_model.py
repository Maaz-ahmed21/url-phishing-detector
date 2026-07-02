import pandas as pd

df = pd.read_csv(r"D:\Mini project\backend\malicious_phish.csv")
print(df.head())
print(df.columns)
df = df.drop_duplicates()
print(df.duplicated().sum())