import hashlib
import requests
import os

class OSINTScanner:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"

    def calculate_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan(self, file_path):
        file_hash = self.calculate_hash(file_path)
        
        if not self.api_key:
            return {
                "status": "error",
                "hash": file_hash,
                "message": "VirusTotal API Key missing. Skipping OSINT reputation.",
                "detections": 0,
                "total_engines": 0,
                "method": "Global Reputation Analysis (Disabled)"
            }

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()["data"]["attributes"]
                return {
                    "status": "success",
                    "hash": file_hash,
                    "detections": data["last_analysis_stats"]["malicious"],
                    "total_engines": sum(data["last_analysis_stats"].values()),
                    "family": data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown"),
                    "last_seen": data.get("last_analysis_date"),
                    "method": "VirusTotal Live API"
                }
            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "hash": file_hash,
                    "message": "File never seen by global intelligence network.",
                    "detections": 0,
                    "total_engines": 0,
                    "method": "VirusTotal Live API"
                }
            else:
                return {
                    "status": "error",
                    "hash": file_hash,
                    "message": "VirusTotal API rate limit or error.",
                    "detections": 0,
                    "total_engines": 0,
                    "method": "VirusTotal Live API"
                }
        except Exception as e:
            return {
                "status": "error",
                "hash": file_hash,
                "message": f"Connection Error: {str(e)}",
                "detections": 0,
                "total_engines": 0,
                "method": "VirusTotal Live API"
            }
