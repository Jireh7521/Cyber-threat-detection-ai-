import pandas as pd
from sklearn.preprocessing import StandardScaler

def load_and_process(file_path):
    df = pd.read_csv(file_path)
    df = df.dropna()
    df.columns = df.columns.str.strip()
    df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    X = df.select_dtypes(include=['number'])
    y = X['Label']
    X = X.drop('Label', axis=1)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, y, scaler