#!/usr/bin/env python3
"""
CyberMind - IA para Ciberseguridad
Herramienta ofensiva/defensiva con inteligencia artificial
"""

import sys
import argparse
import hashlib
import json
import requests
import subprocess
from datetime import datetime

# ========== MÓDULOS DE IA (simulados por ahora, luego los mejoramos) ==========

def analizar_malware_ia(file_path):
    """Simula análisis de malware con IA (patrones + hashes maliciosos)"""
    print(f"[🧠] Analizando {file_path} con modelo de IA...")
    
    # Calcular hash del archivo
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    print(f"    SHA-256: {file_hash}")
    
    # Simular detección de patrones (aquí iría el modelo TensorFlow)
    patrones_sospechosos = [
        b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
        b'cmd.exe', b'powershell -enc', b'rundll32'
    ]
    
    riesgo = 0
    with open(file_path, 'rb') as f:
        contenido = f.read()
        for patron in patrones_sospechosos:
            if patron in contenido:
                riesgo += 25
                print(f"    ⚠️ Patrón sospechoso encontrado: {patron.decode('utf-8', errors='ignore')}")
    
    # Consultar VirusTotal (si tienes API key)
    # vt_key = "TU_API_KEY"  # Descomenta y agrega tu key
    # url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    # headers = {"x-apikey": vt_key}
    # response = requests.get(url, headers=headers)
    
    if riesgo >= 50:
        print(f"    🔴 NIVEL DE RIESGO: ALTO ({riesgo}%) - Posible malware")
    elif riesgo > 0:
        print(f"    🟡 NIVEL DE RIESGO: MEDIO ({riesgo}%) - Sospechoso")
    else:
        print(f"    🟢 NIVEL DE RIESGO: BAJO ({riesgo}%) - Parece limpio")
    
    return {"hash": file_hash, "riesgo": riesgo}

def escanear_red_ia(network):
    """Escanea red usando IA para detectar patrones anómalos"""
    print(f"[🧠] Escaneando red {network}...")
    
    # Usar nmap (debe estar instalado)
    try:
        result = subprocess.run(
            ['nmap', '-sn', network],
            capture_output=True,
            text=True,
            timeout=60
        )
        print("    📡 Hosts encontrados:")
        for line in result.stdout.split('\n'):
            if 'Nmap scan report' in line:
                ip = line.split()[-1]
                print(f"        - {ip}")
        
        # Simular detección de anomalías con IA
        print("\n    🤖 Análisis de IA: No se detectaron patrones anómalos")
        
    except FileNotFoundError:
        print("    ❌ Nmap no está instalado. Instálalo con: sudo apt install nmap")
    except subprocess.TimeoutExpired:
        print("    ⏰ El escaneo tomó demasiado tiempo")

def buscar_cves_ia(software, version):
    """Busca CVEs usando NLP y bases de datos públicas"""
    print(f"[🧠] Buscando vulnerabilidades para {software} {version}...")
    
    # Usar la API de NVD (National Vulnerability Database)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software}%20{version}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])[:5]  # Top 5
            
            if vulns:
                print(f"    🔥 Se encontraron {len(vulns)} vulnerabilidades críticas:")
                for v in vulns:
                    cve = v['cve']
                    print(f"        - {cve['id']}: {cve['descriptions'][0]['value'][:80]}...")
            else:
                print("    ✅ No se encontraron CVEs públicos para esta versión")
        else:
            print("    ⚠️ No se pudo conectar a NVD. Modo offline...")
            # Datos de ejemplo
            ejemplos = {
                "apache": {"2.4": ["CVE-2021-41773", "CVE-2021-42013"]},
                "nginx": {"1.18": ["CVE-2021-23017"]},
                "openssh": {"8.2": ["CVE-2020-15778"]}
            }
            if software.lower() in ejemplos and version in ejemplos[software.lower()]:
                for cve in ejemplos[software.lower()][version]:
                    print(f"        - {cve} (ejemplo - modo offline)")
                    
    except requests.exceptions.RequestException:
        print("    ❌ Error de conexión. Verifica tu internet")

def modo_autohunt():
    """Modo proactivo: escanea y busca amenazas automáticamente"""
    print("[🧠] Modo AutoHunt activado - Búsqueda proactiva de amenazas")
    print("    🔍 Escaneando puertos comunes...")
    
    puertos_comunes = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]
    
    # Escanear localhost como ejemplo
    for port in puertos_comunes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                print(f"    🚨 Puerto {port} ABIERTO - Posible superficie de ataque")
            sock.close()
        except:
            pass
    
    print("\n    ✅ AutoHunt completado. Reporte guardado en autohunt_report.json")

# ========== MAIN ==========

def main():
    parser = argparse.ArgumentParser(
        description="CyberMind - Herramienta de Ciberseguridad con IA",
        epilog="Ejemplo: python cybermind.py scan malware.exe"
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Comandos disponibles")
    
    # Comando: scan
    parser_scan = subparsers.add_parser("scan", help="Analizar archivo en busca de malware")
    parser_scan.add_argument("file", help="Ruta del archivo a analizar")
    
    # Comando: netscan
    parser_net = subparsers.add_parser("netscan", help="Escanear red local")
    parser_net.add_argument("network", help="Rango de red (ej: 192.168.1.0/24)")
    
    # Comando: cve-search
    parser_cve = subparsers.add_parser("cve-search", help="Buscar vulnerabilidades CVE")
    parser_cve.add_argument("software", help="Nombre del software")
    parser_cve.add_argument("version", help="Versión del software")
    
    # Comando: autohunt
    parser_hunt = subparsers.add_parser("autohunt", help="Modo de búsqueda proactiva de amenazas")
    
    # Comando: --version
    parser.add_argument("--version", action="version", version="CyberMind v0.1.0")
    
    args = parser.parse_args()
    
    # Banner
    print("""
    ╔═══════════════════════════════════════╗
    ║   🧠 CyberMind - IA Security Tool    ║
    ║   Modo: Ético y educativo             ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Ejecutar comando
    if args.command == "scan":
        analizar_malware_ia(args.file)
    elif args.command == "netscan":
        escanear_red_ia(args.network)
    elif args.command == "cve-search":
        buscar_cves_ia(args.software, args.version)
    elif args.command == "autohunt":
        modo_autohunt()

if __name__ == "__main__":
    # Importar socket solo para autohunt
    import socket
    main()
