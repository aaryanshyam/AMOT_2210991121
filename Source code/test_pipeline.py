import pytest
from engines.static_analyzer import StaticAnalyzer
from engines.ml_detector import MLDetector
from engines.yara_scanner import YaraScanner
import os

def test_static_analyzer_empty():
    # Test with a non-existent file or empty file
    analyzer = StaticAnalyzer("non_existent.exe")
    results = analyzer.analyze()
    assert "error" in results

def test_ml_detector_empirical():
    detector = MLDetector()
    static_results = {
        "entropy": 8.5,
        "suspicious_imports_count": 5,
        "mitre_techniques": ["T1486"]
    }
    prediction = detector.predict(static_results)
    assert prediction["score"] > 50
    assert prediction["method"] == "Empirical-Heuristic"

def test_yara_scanner_no_rules():
    scanner = YaraScanner(rules_dir="temp_empty_rules")
    results = scanner.scan("any_file.exe")
    assert "error" in results or results["matches_count"] == 0
