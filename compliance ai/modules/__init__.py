"""
Compliance AI - Core Modules
============================
ML-driven compliance automation system modules.
"""

from modules.trainer import ComplianceTrainer, FeatureExtractor
from modules.collector import ComplianceCollector
from modules.inference import ComplianceInference, ComplianceScoreCalculator, ReportGenerator
from modules import utils

__version__ = "1.0.0"
__all__ = [
    "ComplianceTrainer",
    "FeatureExtractor",
    "ComplianceCollector",
    "ComplianceInference",
    "ComplianceScoreCalculator",
    "ReportGenerator",
    "utils",
]