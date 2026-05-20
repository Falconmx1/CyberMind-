import requests
import os
from dotenv import load_dotenv

load_dotenv()

class VirusTotalScanner:
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = "https://www.virustotal.com/api/v3"
    
    def scan_hash(self, file_hash):
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        headers = {"x-apikey": self.api_key}
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "malicious": stats['malicious'],
                    "suspicious": stats['suspicious'],
                    "undetected": stats['undetected'],
                    "total_engines": sum(stats.values())
                }
            else:
                return {"error": "Hash not found in VirusTotal"}
        except Exception as e:
            return {"error": str(e)}
    
    def upload_file(self, file_path):
        """Sube un archivo para análisis"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        headers = {"x-apikey": self.api_key}
        url = f"{self.base_url}/files"
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, headers=headers, files=files)
                return response.json()
        except Exception as e:
            return {"error": str(e)}
