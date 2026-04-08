from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
from data_processing import load_and_process

X, y, scaler = load_and_process("data/Friday-WorkingHours-Afternoon-DDos.csv")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(model, "models/model.pkl")
joblib.dump(scaler, "models/scaler.pkl")
print("Model and scaler saved ✅")