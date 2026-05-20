#!/usr/bin/env python3
"""
Entrenamiento de modelo de IA para detección de malware
Usa características de archivos (bytes, entropía, secciones, etc.)
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import joblib
import os
import hashlib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

def extract_features(file_path):
    """Extrae características de un archivo para análisis"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        if len(data) == 0:
            return None
            
        # Características básicas
        features = {
            'size': len(data),
            'entropy': calculate_entropy(data),
            'byte_mean': np.mean(list(data[:min(1000, len(data))])),
            'byte_std': np.std(list(data[:min(1000, len(data))])),
            'num_sections': count_sections(data),
            'has_pe_signature': 1 if data[:2] == b'MZ' else 0,
            'has_elf_magic': 1 if data[:4] == b'\x7fELF' else 0,
        }
        
        # Histograma de bytes (256 features)
        hist = np.histogram(list(data[:min(10000, len(data))]), bins=32, range=(0,256))[0]
        for i, h in enumerate(hist):
            features[f'byte_hist_{i}'] = h / max(1, len(data))
            
        return features
    except:
        return None

def calculate_entropy(data):
    """Calcula entropía de Shannon"""
    if not data:
        return 0
    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
    probabilities = byte_counts / len(data)
    probabilities = probabilities[probabilities > 0]
    return -np.sum(probabilities * np.log2(probabilities))

def count_sections(data):
    """Cuenta secciones PE/ELF"""
    if data[:2] == b'MZ':  # PE file
        # Parsing básico de PE
        return 4  # Valor por defecto
    return 1

def create_model(input_dim):
    """Crea modelo de deep learning"""
    model = keras.Sequential([
        layers.Dense(128, activation='relu', input_dim=input_dim),
        layers.Dropout(0.3),
        layers.Dense(64, activation='relu'),
        layers.Dropout(0.2),
        layers.Dense(32, activation='relu'),
        layers.Dense(1, activation='sigmoid')
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy', 'precision', 'recall']
    )
    
    return model

def train_model(malware_dir, benign_dir):
    """Entrena el modelo con datasets"""
    print("🧠 Entrenando modelo de detección de malware...")
    
    features_list = []
    labels = []
    
    # Cargar muestras de malware
    print("📂 Cargando muestras de malware...")
    for file in os.listdir(malware_dir)[:1000]:  # Limitar a 1000 por ahora
        path = os.path.join(malware_dir, file)
        feats = extract_features(path)
        if feats:
            features_list.append(feats)
            labels.append(1)
    
    # Cargar muestras benignas
    print("📂 Cargando muestras benignas...")
    for file in os.listdir(benign_dir)[:1000]:
        path = os.path.join(benign_dir, file)
        feats = extract_features(path)
        if feats:
            features_list.append(feats)
            labels.append(0)
    
    # Convertir a DataFrame
    df = pd.DataFrame(features_list)
    X = df.fillna(0).values
    y = np.array(labels)
    
    # Escalar características
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    
    # Dividir datos
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Crear y entrenar modelo
    model = create_model(X.shape[1])
    
    # Detectar GPU
    gpus = tf.config.list_physical_devices('GPU')
    if gpus:
        print(f"🚀 GPU detectada: {gpus[0]}")
        tf.config.experimental.set_memory_growth(gpus[0], True)
    else:
        print("💻 Usando CPU para entrenamiento")
    
    # Entrenar
    history = model.fit(
        X_train, y_train,
        epochs=20,
        batch_size=32,
        validation_data=(X_test, y_test),
        verbose=1
    )
    
    # Evaluar
    test_loss, test_acc, test_prec, test_rec = model.evaluate(X_test, y_test)
    print(f"\n✅ Modelo entrenado!")
    print(f"   Accuracy: {test_acc:.4f}")
    print(f"   Precision: {test_prec:.4f}")
    print(f"   Recall: {test_rec:.4f}")
    
    # Guardar modelo y scaler
    model.save('malware_model.h5')
    joblib.dump(scaler, 'scaler.pkl')
    print("💾 Modelo guardado como 'malware_model.h5'")
    
    return model, scaler

if __name__ == "__main__":
    # Configura rutas de tus datasets
    train_model(
        malware_dir="data/malware_samples/",
        benign_dir="data/benign_samples/"
    )
