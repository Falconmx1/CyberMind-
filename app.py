#!/usr/bin/env python3
"""
CyberMind API REST - Endpoints para integración externa
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import hashlib
from datetime import datetime
import threading
import json

# Importar plugins
from plugins.shodan_plugin import ShodanScanner
from plugins.virustotal_plugin import VirusTotalScanner
from models.detector import MalwareDetector

app = Flask(__name__)
CORS(app)  # Permitir peticiones desde cualquier origen

# Inicializar componentes
detector = MalwareDetector()
shodan = ShodanScanner()
vt = VirusTotalScanner()

# Almacenamiento temporal de amenazas
threats_db = []
alerts_db = []

# ========== ENDPOINTS ==========

@app.route('/')
def index():
    """Dashboard web"""
    return render_template('dashboard.html')

@app.route('/api/health', methods=['GET'])
def health():
    """Verificar estado del servicio"""
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """Analizar archivo en busca de malware"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    temp_path = f"/tmp/{file.filename}"
    file.save(temp_path)
    
    # Analizar con IA
    result = detector.predict(temp_path)
    
    # Calcular hash
    with open(temp_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    result['sha256'] = file_hash
    
    # Consultar VirusTotal
    vt_result = vt.scan_hash(file_hash)
    if vt_result:
        result['virustotal'] = vt_result
    
    # Guardar en DB temporal
    threat = {
        "id": len(threats_db),
        "timestamp": datetime.now().isoformat(),
        "type": "file",
        "hash": file_hash,
        "result": result
    }
    threats_db.append(threat)
    
    # Limpiar
    os.remove(temp_path)
    
    return jsonify(result)

@app.route('/api/scan/ip', methods=['POST'])
def scan_ip():
    """Escanea una IP con Shodan"""
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "IP required"}), 400
    
    result = shodan.scan_ip(ip)
    
    threat = {
        "id": len(threats_db),
        "timestamp": datetime.now().isoformat(),
        "type": "ip",
        "target": ip,
        "result": result
    }
    threats_db.append(threat)
    
    return jsonify(result)

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Obtener todas las amenazas detectadas"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(threats_db[-limit:])

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Obtener alertas generadas"""
    return jsonify(alerts_db)

@app.route('/api/threats/stats', methods=['GET'])
def get_stats():
    """Estadísticas de amenazas"""
    malware_count = sum(1 for t in threats_db if t.get('result', {}).get('is_malware'))
    return jsonify({
        "total_scans": len(threats_db),
        "malware_detected": malware_count,
        "ips_scanned": sum(1 for t in threats_db if t['type'] == 'ip'),
        "files_scanned": sum(1 for t in threats_db if t['type'] == 'file')
    })

# ========== SISTEMA DE ALERTAS ==========

def check_for_threats():
    """Monitorea amenazas y genera alertas"""
    for threat in threats_db:
        if threat not in alerts_db:
            if threat['type'] == 'file' and threat['result'].get('is_malware'):
                alerts_db.append({
                    "id": len(alerts_db),
                    "timestamp": datetime.now().isoformat(),
                    "severity": "high",
                    "message": f"Malware detectado: {threat['hash']}",
                    "threat": threat
                })
            elif threat['type'] == 'ip' and threat['result'].get('vulnerabilities'):
                alerts_db.append({
                    "id": len(alerts_db),
                    "timestamp": datetime.now().isoformat(),
                    "severity": "medium",
                    "message": f"IP vulnerable: {threat['target']}",
                    "threat": threat
                })

# Hilo para monitoreo automático
def alert_monitor():
    while True:
        check_for_threats()
        threading.Event().wait(10)  # Cada 10 segundos

if __name__ == '__main__':
    # Iniciar monitor de alertas en segundo plano
    monitor_thread = threading.Thread(target=alert_monitor, daemon=True)
    monitor_thread.start()
    
    # Iniciar servidor
    app.run(host='0.0.0.0', port=5000, debug=True)
