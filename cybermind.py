#!/usr/bin/env python3
"""
CyberMind - IA para Ciberseguridad
Uso: python cybermind.py [comando] [opciones]
"""

import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="CyberMind AI Security Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan malware
    parser_scan = subparsers.add_parser("scan", help="Analizar archivo")
    parser_scan.add_argument("file", help="Ruta del archivo a analizar")

    # Net scan
    parser_net = subparsers.add_parser("netscan", help="Escanear red")
    parser_net.add_argument("network", help="Ej: 192.168.1.0/24")

    # CVE search
    parser_cve = subparsers.add_parser("cve-search", help="Buscar CVEs")
    parser_cve.add_argument("software", help="Nombre del software")
    parser_cve.add_argument("version", help="Versión")

    args = parser.parse_args()

    if args.command == "scan":
        print(f"[🧠] Analizando {args.file} con IA...")
        # Aquí llamarás al modelo
    elif args.command == "netscan":
        print(f"[🧠] Escaneando red {args.network}...")
    elif args.command == "cve-search":
        print(f"[🧠] Buscando CVEs para {args.software} {args.version}...")

if __name__ == "__main__":
    main()
