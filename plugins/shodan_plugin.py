import os
import shodan
from dotenv import load_dotenv

load_dotenv()

class ShodanScanner:
    def __init__(self):
        self.api_key = os.getenv('SHODAN_API_KEY')
        self.api = None
        if self.api_key:
            self.api = shodan.Shodan(self.api_key)
    
    def scan_ip(self, ip):
        if not self.api:
            return {"error": "Shodan API key not configured"}
        
        try:
            info = self.api.host(ip)
            return {
                "ip": ip,
                "country": info.get('country_name'),
                "org": info.get('org'),
                "open_ports": info.get('ports'),
                "vulnerabilities": info.get('vulns', []),
                "hostnames": info.get('hostnames')
            }
        except Exception as e:
            return {"error": str(e)}
    
    def search(self, query):
        if not self.api:
            return {"error": "Shodan API key not configured"}
        
        try:
            results = self.api.search(query)
            return {
                "total": results['total'],
                "matches": [{
                    "ip": match['ip_str'],
                    "port": match['port'],
                    "data": match['data'][:200]
                } for match in results['matches'][:10]]
            }
        except Exception as e:
            return {"error": str(e)}
