from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np

app = Flask(__name__)

# Load model and scaler
model = joblib.load("models/model.pkl")
scaler = joblib.load("models/scaler.pkl")

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/predict', methods=['POST'])
def predict():
    try:
        features = request.json['features']
        features_scaled = scaler.transform([features])
        prediction = model.predict(features_scaled)[0]
        return jsonify({
            "prediction": int(prediction),
            "message": "Threat Detected ⚠️" if prediction == 1 else "Normal Traffic ✅"
        })
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)