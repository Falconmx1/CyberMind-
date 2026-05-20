import tensorflow as tf
import joblib
import numpy as np
from train import extract_features

class MalwareDetector:
    def __init__(self, model_path='malware_model.h5', scaler_path='scaler.pkl'):
        self.model = tf.keras.models.load_model(model_path)
        self.scaler = joblib.load(scaler_path)
    
    def predict(self, file_path):
        features = extract_features(file_path)
        if not features:
            return {"error": "No se pudieron extraer características"}
        
        # Convertir a array
        X = np.array([list(features.values())])
        X_scaled = self.scaler.transform(X)
        
        # Predicción
        prob = self.model.predict(X_scaled)[0][0]
        is_malware = prob > 0.5
        
        return {
            "file": file_path,
            "is_malware": bool(is_malware),
            "confidence": float(prob if is_malware else 1-prob),
            "malware_probability": float(prob)
        }
