"""
AMOT FastAPI Backend for Ransomware & Forensics Analyser.
"""

import os
import shutil
import uuid
import traceback

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from engines.static_analyzer import StaticAnalyzer
from engines.ml_detector import MLDetector
from engines.yara_scanner import YaraScanner
from engines.detonation_manager import DetonationManager
from engines.osint_scanner import OSINTScanner
from utils.db_manager import DatabaseManager

app = FastAPI(title="AMOT Ransomware & Forensics Analyser API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
RULES_DIR = "rules"
MODELS_DIR = "models"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize Engines
ml_detector = MLDetector(models_dir=MODELS_DIR)
yara_scanner = YaraScanner(rules_dir=RULES_DIR)
detonation_manager = DetonationManager(sandbox_type="simulated")
osint_scanner = OSINTScanner()
db_manager = DatabaseManager()


@app.get("/")
async def root():
    """
    Root endpoint to verify API health.
    """
    return {"message": "AMOT Ransomware & Forensics Analyser API is running"}


@app.get("/history")
async def get_history():
    """
    Retrieve all previous scan results from the database.
    """
    return db_manager.get_history()


@app.delete("/history/{scan_id}")
async def delete_history(scan_id: int):
    """
    Remove a specific scan record from the history.
    """
    if db_manager.delete_scan(scan_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Scan not found")


@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Perform a complete hybrid analysis on a suspected malware file.
    """
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    
    try:
        # 0. Save File
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # 1. Static Analysis
        static_analyzer = StaticAnalyzer(file_path)
        static_results = static_analyzer.analyze()
        
        # 2. ML Detection (Multi-Model Ensemble Consulting)
        ml_results = ml_detector.predict(static_results)
        
        # 3. YARA Scan
        yara_results = yara_scanner.scan(file_path)
        
        # 4. Detonation (Safe/Simulated)
        detonation_results = detonation_manager.detonate(file_path, static_results)
        
        # 5. OSINT Reputation
        osint_results = osint_scanner.scan(file_path)
        
        # 6. Aggregate Results
        is_malicious = (
            ml_results["score"] > 70 or 
            yara_results["matches_count"] > 0 or 
            osint_results.get("detections", 0) > 0
        )
        verdict = "Malicious" if is_malicious else "Likely Benign"
        
        ml_score = ml_results["score"]
        osint_score = min(osint_results.get("detections", 0) * 10, 100)
        threat_score = max(ml_score, osint_score)
        
        final_report = {
            "file_info": {
                "id": file_id,
                "filename": file.filename,
                "size": os.path.getsize(file_path)
            },
            "static_analysis": static_results,
            "ml_detection": ml_results,
            "yara_scan": yara_results,
            "detonation_report": detonation_results,
            "osint_report": osint_results,
            "verdict": verdict,
            "threat_score": threat_score
        }
        
        # 7. Save to Database
        db_manager.save_scan(final_report["file_info"], verdict, threat_score, final_report)
        
        return final_report

    except Exception as e:
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Optional: cleanup uploaded file after analysis if needed
        # os.remove(file_path)
        pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
