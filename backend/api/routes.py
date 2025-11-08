"""
FastAPI Routes for Compliance AI Dashboard
==========================================
Production-ready API endpoints for frontend integration.
"""

import sys
from pathlib import Path

# Add parent directory to path to allow imports
backend_dir = Path(__file__).parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import logging
from datetime import datetime
import time

# Import your existing modules
from core.collector import ComplianceCollector
from core.trainer import ComplianceTrainer
from core.auditor import ComplianceAuditor
from services.report_service import ReportService
from services.enhanced_report_service import EnhancedReportService
from services.ultra_comprehensive_report_service import UltraComprehensiveReportService
from services.remediation_service import RemediationService, Platform
from services.visualization_service import VisualizationService
from utils.logger import setup_logger

logger = setup_logger("api")

# Initialize FastAPI
app = FastAPI(
    title="Compliance AI Engine API",
    description="Enterprise Compliance & Audit Intelligence",
    version="1.0.0"
)

# CORS Configuration - Allow common development origins
# IMPORTANT: CORS middleware must be added FIRST, before other middleware
# Using CORSMiddleware with proper configuration
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Custom CORS middleware to ensure headers are always added
class CORSMiddlewareCustom(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Handle preflight requests
        if request.method == "OPTIONS":
            origin = request.headers.get("origin")
            if origin in allowed_origins:
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
                        "Access-Control-Allow-Headers": request.headers.get("access-control-request-headers", "Content-Type, Authorization"),
                        "Access-Control-Max-Age": "3600",
                    }
                )
        
        # Process the request
        start_time = time.time()
        origin = request.headers.get("origin")
        
        # Log incoming request (only for browser requests)
        user_agent = request.headers.get('user-agent', '')
        if 'Mozilla' in user_agent or 'Chrome' in user_agent or 'Firefox' in user_agent or 'Safari' in user_agent:
            logger.info(f"🌐 BROWSER REQUEST: {request.method} {request.url.path}")
            logger.info(f"   Origin: {origin}")
            logger.info(f"   User-Agent: {user_agent[:50]}...")
        
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            # Always add CORS headers for browser requests
            if origin in allowed_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
            
            if 'Mozilla' in user_agent or 'Chrome' in user_agent or 'Firefox' in user_agent or 'Safari' in user_agent:
                logger.info(f"✅ BROWSER RESPONSE: {request.method} {request.url.path} -> {response.status_code} ({process_time:.3f}s)")
                logger.info(f"   CORS Headers Added: {origin}")
            
            return response
        except Exception as e:
            logger.error(f"❌ Error processing {request.method} {request.url.path}: {e}", exc_info=True)
            # Even on error, add CORS headers
            if origin in allowed_origins:
                error_response = JSONResponse(
                    content={"error": str(e), "detail": str(e)},
                    status_code=500
                )
                error_response.headers["Access-Control-Allow-Origin"] = origin
                error_response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH"
                error_response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
                return error_response
            raise

# Add custom CORS middleware AFTER the built-in one
app.add_middleware(CORSMiddlewareCustom)

# Global state
scan_state = {
    "status": "idle",
    "progress": 0,
    "data": None,
    "error": None
}

# Paths (relative to backend directory)
OUTPUTS_DIR = backend_dir / "data" / "collected"
REPORTS_DIR = backend_dir / "reports"
MODELS_DIR = backend_dir / "models"
FRAMEWORKS_DIR = backend_dir / "config" / "frameworks"

OUTPUTS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
MODELS_DIR.mkdir(exist_ok=True)


# ============================================================================
# CORE API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "operational",
        "service": "Compliance AI Engine",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "service": "Compliance AI Engine API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/test")
async def test_connection():
    """Test endpoint to verify CORS and connectivity."""
    return {
        "success": True,
        "message": "Backend is accessible",
        "timestamp": datetime.now().isoformat(),
        "cors": "enabled"
    }


def run_collection_task():
    """Background task to run data collection."""
    try:
        logger.info("🔍 Starting background data collection...")
        scan_state["status"] = "collecting"
        scan_state["progress"] = 10
        scan_state["error"] = None
        
        # Run collector with timeout protection
        collector = ComplianceCollector()
        data = collector.collect_all()
        
        # Save collected data
        output_file = OUTPUTS_DIR / f"compliance_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        scan_state["progress"] = 20
        scan_state["data"] = data
        scan_state["status"] = "idle"  # Set back to idle when complete
        logger.info(f"✅ Data collection complete: {output_file}")
        
    except Exception as e:
        logger.error(f"❌ Collection failed: {e}", exc_info=True)
        scan_state["status"] = "error"
        scan_state["error"] = str(e)

@app.post("/api/collect")
async def collect_data(background_tasks: BackgroundTasks, request: Request):
    """
    Step 1: Collect compliance data from the system.
    Runs collection in background to avoid timeout.
    """
    try:
        # Log the incoming request for debugging
        logger.info(f"📥 Received POST /api/collect from {request.client.host if request.client else 'unknown'}")
        logger.info(f"📋 Origin: {request.headers.get('origin', 'none')}")
        
        # Reset error state
        scan_state["error"] = None
        
        # Check if collection is already in progress
        if scan_state["status"] == "collecting":
            response_data = {
                "success": True,
                "message": "Collection already in progress",
                "status": "collecting",
                "progress": scan_state["progress"],
                "timestamp": datetime.now().isoformat()
            }
            response = JSONResponse(content=response_data)
            origin = request.headers.get("origin")
            if origin in allowed_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
            return response
        
        # Start collection in background
        background_tasks.add_task(run_collection_task)
        
        logger.info("🚀 Data collection started in background")
        
        # Return immediately with CORS headers
        response_data = {
            "success": True,
            "message": "Data collection started",
            "status": "collecting",
            "progress": 10,
            "timestamp": datetime.now().isoformat()
        }
        
        response = JSONResponse(content=response_data)
        origin = request.headers.get("origin")
        if origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
        return response
        
    except Exception as e:
        logger.error(f"❌ Failed to start collection: {e}", exc_info=True)
        scan_state["status"] = "error"
        scan_state["error"] = str(e)
        error_response = JSONResponse(
            content={"error": str(e), "detail": str(e)},
            status_code=500
        )
        origin = request.headers.get("origin")
        if origin in allowed_origins:
            error_response.headers["Access-Control-Allow-Origin"] = origin
        return error_response


@app.post("/api/train")
async def train_model():
    """
    Step 2: Train ML model on collected data.
    """
    try:
        logger.info("🎯 Starting model training...")
        scan_state["status"] = "training"
        scan_state["progress"] = 30
        
        # Find latest data file
        data_files = sorted(OUTPUTS_DIR.glob("compliance_data_*.json"))
        if not data_files:
            raise ValueError("No compliance data found. Run /api/collect first.")
        
        latest_data = data_files[-1]
        
        # Train model
        trainer = ComplianceTrainer(model_type='rf')
        result = trainer.train(
            data_path=latest_data,
            output_dir=MODELS_DIR,
            model_name="compliance_model"
        )
        
        if not result:
            raise ValueError("Model training failed")
        
        # Load metrics from summary file if it exists
        metrics = {}
        summary_file = MODELS_DIR / "compliance_model_summary.json"
        if summary_file.exists():
            try:
                with open(summary_file, 'r') as f:
                    summary = json.load(f)
                    metrics = summary.get("metrics", {})
            except Exception as e:
                logger.warning(f"Could not load metrics from summary: {e}")
        
        scan_state["progress"] = 50
        logger.info("✅ Model training complete")
        
        return {
            "success": True,
            "message": "Model training complete",
            "model_path": str(MODELS_DIR / "compliance_model.joblib"),
            "metrics": metrics,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Training failed: {e}", exc_info=True)
        scan_state["status"] = "error"
        scan_state["error"] = str(e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/report")
async def get_audit_report():
    """
    Step 3: Run comprehensive compliance audit.
    """
    try:
        logger.info("📊 Running compliance audit...")
        scan_state["status"] = "auditing"
        scan_state["progress"] = 60
        
        # Find latest data file
        data_files = sorted(OUTPUTS_DIR.glob("compliance_data_*.json"))
        if not data_files:
            raise ValueError("No compliance data found. Run /api/collect first.")
        
        latest_data = data_files[-1]
        
        # Load data
        with open(latest_data) as f:
            compliance_data = json.load(f)
        
        # Run audit
        auditor = ComplianceAuditor(frameworks_dir=FRAMEWORKS_DIR)
        audit_results = auditor.audit_all_frameworks(compliance_data)
        
        # Save audit results
        audit_file = OUTPUTS_DIR / f"audit_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(audit_file, 'w') as f:
            json.dump(audit_results, f, indent=2, default=str)
        
        scan_state["progress"] = 80
        scan_state["data"] = audit_results
        logger.info("✅ Audit complete")
        
        return {
            "success": True,
            "audit_results": audit_results,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Audit failed: {e}", exc_info=True)
        scan_state["status"] = "error"
        scan_state["error"] = str(e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/frontend")
async def get_frontend_report():
    """
    Step 4: Generate frontend-optimized JSON report.
    This is the key endpoint your React dashboard will consume!
    """
    try:
        logger.info("📱 Generating frontend report...")
        scan_state["status"] = "generating_reports"
        scan_state["progress"] = 90
        
        # Find latest audit results
        audit_files = sorted(OUTPUTS_DIR.glob("audit_results_*.json"))
        if not audit_files:
            raise ValueError("No audit results found. Run /api/audit/report first.")
        
        latest_audit = audit_files[-1]
        
        # Load audit results
        with open(latest_audit) as f:
            audit_results = json.load(f)
        
        # Generate comprehensive reports
        config_path = backend_dir / "config.yaml"
        report_service = ReportService(config_path=str(config_path))
        
        # Prepare data structure for frontend
        frontend_data = report_service._generate_frontend_json({
            "company_name": audit_results.get("company_name", "Unknown"),
            "audit_results": audit_results
        })
        
        # Save frontend JSON
        frontend_file = REPORTS_DIR / f"frontend_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(frontend_file, 'w') as f:
            json.dump(frontend_data, f, indent=2, default=str)
        
        scan_state["progress"] = 100
        scan_state["status"] = "complete"
        logger.info("✅ Frontend report generated")
        
        return frontend_data
        
    except Exception as e:
        logger.error(f"❌ Report generation failed: {e}", exc_info=True)
        scan_state["status"] = "error"
        scan_state["error"] = str(e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/download/{format}")
async def download_report(format: str):
    """
    Download reports in various formats (pdf, excel, json).
    BULLETPROOF: Works with any data structure, any file location.
    """
    try:
        logger.info(f"📥 Downloading report as {format}...")
        
        # Find the latest audit results - CHECK ALL POSSIBLE LOCATIONS
        audit_files = (
            list(REPORTS_DIR.glob("audit_*.json")) + 
            list(OUTPUTS_DIR.glob("audit_*.json")) +
            list(REPORTS_DIR.glob("frontend_report_*.json")) +
            list(REPORTS_DIR.glob("*_report_*.json"))
        )
        
        if not audit_files:
            logger.error("No audit files found anywhere")
            raise HTTPException(
                status_code=404, 
                detail="No audit results available. Please run a compliance scan first."
            )
        
        if format == "json":
            # Return latest real-time JSON report (prioritize frontend_report)
            frontend_reports = sorted(REPORTS_DIR.glob("frontend_report_*.json"))
            all_json_files = frontend_reports + sorted(REPORTS_DIR.glob("*.json"))

            if all_json_files:
                latest_json = sorted(all_json_files, key=lambda x: x.stat().st_mtime)[-1]
                logger.info(f"📄 Returning real-time JSON: {latest_json.name}")

                # Load and log summary
                with open(latest_json) as f:
                    data = json.load(f)
                logger.info(f"   Total Rules: {data.get('key_metrics', {}).get('total_rules_checked', 0)}")
                logger.info(f"   Overall Score: {data.get('dashboard_summary', {}).get('overall_score', 0)}%")

                return FileResponse(
                    latest_json,
                    media_type="application/json",
                    filename="compliance_report.json"
                )
            else:
                raise HTTPException(status_code=404, detail="No JSON report found")
        
        elif format == "pdf":
            # Generate ENHANCED PDF report from latest real-time audit data
            # Prioritize frontend_report files (contain real-time dashboard data)
            frontend_reports = sorted(REPORTS_DIR.glob("frontend_report_*.json"))
            all_audit_files = (
                frontend_reports +
                list(REPORTS_DIR.glob("audit_*.json")) +
                list(OUTPUTS_DIR.glob("audit_*.json"))
            )

            if all_audit_files:
                latest_audit = sorted(all_audit_files, key=lambda x: x.stat().st_mtime)[-1]
                logger.info(f"📄 Using real-time data from: {latest_audit.name}")
                with open(latest_audit) as f:
                    audit_data = json.load(f)
            else:
                raise HTTPException(status_code=404, detail="No audit data available for PDF generation")

            try:
                from services.enhanced_pdf_service import EnhancedPDFService

                pdf_service = EnhancedPDFService(output_dir=str(REPORTS_DIR))

                # Extract company name from real-time data structure
                company_name = (
                    audit_data.get("dashboard_summary", {}).get("company", {}).get("name") or
                    audit_data.get("company_name") or
                    "System"
                )

                logger.info(f"📊 Generating PDF for: {company_name}")
                logger.info(f"   Overall Score: {audit_data.get('dashboard_summary', {}).get('overall_score', 0)}%")

                pdf_path = pdf_service.generate_comprehensive_pdf(
                    audit_results=audit_data,
                    company_name=company_name
                )

                if pdf_path and Path(pdf_path).exists():
                    logger.info(f"✅ PDF generated: {Path(pdf_path).stat().st_size / 1024:.2f} KB")
                    return FileResponse(
                        pdf_path,
                        media_type="application/pdf",
                        filename=f"executive_compliance_report.pdf"
                    )
                else:
                    raise ValueError("PDF generation failed - file not created")
            except Exception as pdf_error:
                logger.error(f"Enhanced PDF generation error: {pdf_error}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(pdf_error)}")
        
        elif format == "excel":
            # Generate Excel report from latest audit
            if audit_files:
                latest_audit = sorted(audit_files)[-1]
                with open(latest_audit) as f:
                    audit_data = json.load(f)
            else:
                raise HTTPException(status_code=404, detail="No audit data available for Excel generation")
            
            config_path = backend_dir / "config.yaml"
            report_service = ReportService(config_path=str(config_path))
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            try:
                excel_path = report_service._generate_excel_report(
                    {"company_name": audit_data.get("company_name", "System"), "audit_results": audit_data},
                    timestamp
                )
                
                if excel_path and Path(excel_path).exists():
                    return FileResponse(
                        excel_path,
                        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        filename=f"compliance_report_{timestamp}.xlsx"
                    )
                else:
                    raise ValueError("Excel generation failed - file not created")
            except Exception as excel_error:
                logger.error(f"Excel generation error: {excel_error}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Excel generation failed: {str(excel_error)}")
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Download failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Download error: {str(e)}")


@app.get("/api/status")
async def get_scan_status(request: Request):
    """
    Get current scan status and progress.
    """
    response_data = {
        "status": scan_state["status"],
        "progress": scan_state["progress"],
        "error": scan_state["error"],
        "timestamp": datetime.now().isoformat()
    }
    
    response = JSONResponse(content=response_data)
    origin = request.headers.get("origin")
    if origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
    return response


# ============================================================================
# ENHANCED REPORTING ENDPOINTS
# ============================================================================

@app.get("/api/reports/enhanced/excel")
async def get_enhanced_excel_report():
    """
    Generate ULTRA COMPREHENSIVE Excel report with:
    - Executive Summary with real-time dashboard data
    - Detailed findings for EVERY rule from actual scan
    - Remediation strategies for ALL failed rules with platform-specific commands
    - Multiple charts, heatmaps, risk matrices based on real data
    - Timeline and cost estimates
    - Category breakdowns from actual compliance results
    BULLETPROOF: Uses real-time scanned data from dashboard.
    """
    try:
        logger.info("📊 Generating ULTRA COMPREHENSIVE Excel report from real-time data...")

        # Get latest audit results - ALL LOCATIONS (prioritize frontend_report for real-time data)
        frontend_reports = sorted(REPORTS_DIR.glob("frontend_report_*.json"))
        audit_files = (
            frontend_reports +
            list(REPORTS_DIR.glob("audit_*.json")) +
            list(OUTPUTS_DIR.glob("audit_*.json")) +
            list(REPORTS_DIR.glob("*_report_*.json"))
        )

        if not audit_files:
            logger.error("No audit data for Excel generation")
            raise HTTPException(
                status_code=404,
                detail="No audit results available. Please run a scan first."
            )

        # Use the latest frontend report (contains real-time dashboard data)
        latest_audit = sorted(audit_files, key=lambda x: x.stat().st_mtime)[-1]
        logger.info(f"📄 Using real-time audit file: {latest_audit.name}")

        with open(latest_audit) as f:
            audit_data = json.load(f)

        # Log data summary for verification
        logger.info(f"📊 Data Summary:")
        logger.info(f"   - Company: {audit_data.get('dashboard_summary', {}).get('company', {}).get('name', 'Unknown')}")
        logger.info(f"   - Overall Score: {audit_data.get('dashboard_summary', {}).get('overall_score', 0)}%")
        logger.info(f"   - Total Rules: {audit_data.get('key_metrics', {}).get('total_rules_checked', 0)}")
        logger.info(f"   - Frameworks: {audit_data.get('key_metrics', {}).get('frameworks_assessed', 0)}")

        # Initialize ULTRA comprehensive report service
        ultra_service = UltraComprehensiveReportService(output_dir=str(REPORTS_DIR))

        # Generate ULTRA comprehensive report with REAL-TIME DATA
        system_name = (
            audit_data.get("dashboard_summary", {}).get("company", {}).get("name") or
            audit_data.get("company_name") or
            audit_data.get("system_name") or
            "Organization"
        )

        excel_file = ultra_service.generate_ultra_comprehensive_excel(
            audit_results=audit_data,
            system_name=system_name
        )

        logger.info(f"✅ ULTRA COMPREHENSIVE Excel report generated: {excel_file}")
        logger.info(f"   File size: {Path(excel_file).stat().st_size / 1024:.2f} KB")

        return FileResponse(
            excel_file,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            filename=Path(excel_file).name
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ ULTRA Excel generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# REMEDIATION ENDPOINTS
# ============================================================================

@app.get("/api/remediation/guidance")
async def get_remediation_guidance():
    """
    Get comprehensive remediation guidance for all failed rules.
    """
    try:
        logger.info("📋 Generating remediation guidance...")

        # Get latest audit results - check multiple locations
        audit_files = (
            list(REPORTS_DIR.glob("audit_*.json")) +
            list(OUTPUTS_DIR.glob("audit_*.json")) +
            list(REPORTS_DIR.glob("frontend_report_*.json"))
        )

        if not audit_files:
            logger.error("No audit files found in any location")
            raise HTTPException(
                status_code=404,
                detail="No audit results available. Please run a compliance scan first."
            )

        # Get the latest audit file
        latest_audit = max(audit_files, key=lambda x: x.stat().st_mtime)
        logger.info(f"Loading audit data from: {latest_audit.name}")

        with open(latest_audit) as f:
            audit_data = json.load(f)

        # Initialize remediation service
        remediation_service = RemediationService(output_dir=str(REPORTS_DIR / "remediation"))

        # Generate guidance for all failed rules
        all_guidance = []

        # Handle different JSON structures
        frameworks = {}

        # Try to find frameworks in different locations
        if 'detailed_frameworks' in audit_data:
            # Frontend JSON format with detailed_frameworks
            frameworks = audit_data['detailed_frameworks']
            logger.info(f"Found detailed_frameworks with {len(frameworks)} frameworks")
        elif 'frameworks' in audit_data:
            frameworks = audit_data['frameworks']
            logger.info(f"Found frameworks with {len(frameworks)} frameworks")
        elif 'audit_results' in audit_data and 'frameworks' in audit_data['audit_results']:
            frameworks = audit_data['audit_results']['frameworks']
            logger.info(f"Found audit_results.frameworks with {len(frameworks)} frameworks")
        else:
            logger.warning("No frameworks found in audit data")
            return JSONResponse(content={
                "total_items": 0,
                "guidance": [],
                "timestamp": datetime.now().isoformat(),
                "message": "No framework data found in audit results"
            })

        # Process each framework
        for fw_name, fw_data in frameworks.items():
            logger.info(f"Processing framework: {fw_name}")

            # Extract failed rules from different possible structures
            failed_rules = []

            # Check for critical_gaps (frontend JSON format)
            if 'critical_gaps' in fw_data:
                failed_rules = fw_data['critical_gaps']
                logger.info(f"Found {len(failed_rules)} critical gaps in {fw_name}")

            # Check for categories with rules
            elif 'categories' in fw_data:
                for cat_name, cat_data in fw_data['categories'].items():
                    cat_rules = cat_data.get('rules', [])
                    # Filter for failed rules
                    failed_rules.extend([r for r in cat_rules if r.get('status') in ['FAIL', 'FAILED', 'MISSING_DATA', 'ERROR']])
                logger.info(f"Found {len(failed_rules)} failed rules from categories in {fw_name}")

            # Check for direct rules list
            elif 'rules' in fw_data:
                all_rules = fw_data['rules']
                failed_rules = [r for r in all_rules if r.get('status') in ['FAIL', 'FAILED', 'MISSING_DATA', 'ERROR']]
                logger.info(f"Found {len(failed_rules)} failed rules in {fw_name}")

            # Generate guidance for each failed rule
            for rule in failed_rules:
                try:
                    # Ensure rule has required fields
                    if not rule.get('rule_id'):
                        logger.warning(f"Skipping rule without rule_id in {fw_name}")
                        continue

                    guidance = remediation_service.generate_remediation_guidance(rule, fw_name)
                    all_guidance.append({
                        'framework': fw_name,
                        'rule_id': rule.get('rule_id'),
                        'description': rule.get('description', 'No description'),
                        'severity': rule.get('severity', 'UNKNOWN'),
                        'category': rule.get('category', 'General'),
                        'guidance': guidance.__dict__
                    })
                except Exception as e:
                    logger.error(f"Error generating guidance for {rule.get('rule_id', 'unknown')}: {e}", exc_info=True)

        logger.info(f"✅ Generated guidance for {len(all_guidance)} rules")

        return JSONResponse(content={
            "total_items": len(all_guidance),
            "guidance": all_guidance,
            "timestamp": datetime.now().isoformat(),
            "source_file": latest_audit.name
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Remediation guidance generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/remediation/scripts/{platform}")
async def get_remediation_scripts(platform: str):
    """
    Generate automated remediation scripts for a specific platform.
    Supported platforms: linux, windows, macos
    """
    try:
        logger.info(f"🔧 Generating remediation scripts for {platform}...")
        
        # Validate platform
        try:
            platform_enum = Platform[platform.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Unsupported platform: {platform}")
        
        # Get latest audit results
        audit_files = list(REPORTS_DIR.glob("audit_*.json")) + list(OUTPUTS_DIR.glob("audit_*.json"))
        if not audit_files:
            raise HTTPException(status_code=404, detail="No audit results available")
        
        latest_audit = sorted(audit_files)[-1]
        with open(latest_audit) as f:
            audit_data = json.load(f)
        
        # Initialize remediation service
        remediation_service = RemediationService(output_dir=str(REPORTS_DIR / "remediation"))
        
        # Collect all failed rules from nested categories structure
        failed_rules = []
        frameworks = audit_data.get('frameworks', {})
        
        for fw_name, fw_data in frameworks.items():
            # Extract rules from categories
            if 'categories' in fw_data:
                for cat_name, cat_data in fw_data['categories'].items():
                    rules = cat_data.get('rules', [])
                    failed_rules.extend([r for r in rules if r.get('status') in ['FAIL', 'MISSING_DATA', 'ERROR', 'FAILED']])
            elif 'rules' in fw_data:
                rules = fw_data.get('rules', [])
                failed_rules.extend([r for r in rules if r.get('status') in ['FAIL', 'MISSING_DATA', 'ERROR', 'FAILED']])
        
        logger.info(f"Found {len(failed_rules)} failed rules for script generation")
        
        # Generate scripts
        generated_scripts = remediation_service.generate_remediation_scripts(failed_rules, platform_enum)
        
        logger.info(f"✅ Generated {len(generated_scripts)} scripts for {platform}")
        
        return JSONResponse(content={
            "platform": platform,
            "total_scripts": len(generated_scripts),
            "scripts": [{"rule_id": rid, "path": str(path)} for rid, path in generated_scripts.items()],
            "timestamp": datetime.now().isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Script generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/remediation/scripts/{platform}/download")
async def download_remediation_scripts(platform: str):
    """
    Download comprehensive remediation scripts for a platform as a zip file.
    Includes both template-based scripts and full OS hardening scripts.
    """
    try:
        logger.info(f"📦 Preparing comprehensive remediation scripts download for {platform}...")

        # Validate platform
        try:
            platform_enum = Platform[platform.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Unsupported platform: {platform}")

        # Initialize remediation service
        remediation_service = RemediationService(output_dir=str(REPORTS_DIR / "remediation"))

        # Generate ZIP with comprehensive hardening scripts
        zip_path = remediation_service.generate_remediation_scripts_zip(platform_enum)

        if not zip_path.exists():
            raise HTTPException(status_code=404, detail=f"Failed to generate scripts for {platform}")

        # Return the ZIP file
        return FileResponse(
            path=zip_path,
            filename=f"remediation_scripts_{platform}.zip",
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=remediation_scripts_{platform}.zip"}
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Scripts download failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# VISUALIZATION ENDPOINTS
# ============================================================================

@app.get("/api/visualizations/dashboard")
async def get_interactive_dashboard():
    """
    Generate interactive Plotly dashboard (HTML).
    """
    try:
        logger.info("📊 Generating interactive dashboard...")
        
        # Get latest audit results
        audit_files = list(REPORTS_DIR.glob("audit_*.json")) + list(OUTPUTS_DIR.glob("audit_*.json"))
        if not audit_files:
            raise HTTPException(status_code=404, detail="No audit results available")
        
        latest_audit = sorted(audit_files)[-1]
        with open(latest_audit) as f:
            audit_data = json.load(f)
        
        # Initialize visualization service
        viz_service = VisualizationService(output_dir=str(REPORTS_DIR / "visualizations"))
        
        # Generate dashboard
        dashboard_file = viz_service.generate_interactive_dashboard(
            audit_results=audit_data,
            company_name=audit_data.get("company_name", "Organization")
        )
        
        logger.info(f"✅ Interactive dashboard generated: {dashboard_file}")
        
        return FileResponse(
            dashboard_file,
            media_type="text/html",
            filename=dashboard_file.name
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Dashboard generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/visualizations/all")
async def generate_all_visualizations():
    """
    Generate all visualizations (dashboard, heatmap, gap analysis, etc.).
    BULLETPROOF: Works with any audit data.
    """
    try:
        logger.info("🎨 Generating all visualizations...")
        
        # Get latest audit results - ALL LOCATIONS
        audit_files = (
            list(REPORTS_DIR.glob("audit_*.json")) + 
            list(OUTPUTS_DIR.glob("audit_*.json")) +
            list(REPORTS_DIR.glob("frontend_report_*.json"))
        )
        
        if not audit_files:
            logger.error("No audit data for visualizations")
            raise HTTPException(
                status_code=404, 
                detail="No audit results available. Please run a scan first."
            )
        
        latest_audit = sorted(audit_files)[-1]
        with open(latest_audit) as f:
            audit_data = json.load(f)
        
        # Initialize visualization service
        viz_service = VisualizationService(output_dir=str(REPORTS_DIR / "visualizations"))
        
        # Generate all visualizations
        visualizations = viz_service.generate_all_visualizations(
            audit_results=audit_data,
            company_name=audit_data.get("company_name", "Organization")
        )
        
        logger.info(f"✅ Generated {len(visualizations)} visualizations")
        
        return JSONResponse(content={
            "total_visualizations": len(visualizations),
            "visualizations": {name: str(path) for name, path in visualizations.items()},
            "timestamp": datetime.now().isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Visualization generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/visualizations/{viz_type}")
async def get_visualization(viz_type: str):
    """
    Get a specific visualization by type.
    Types: heatmap, gap_analysis, risk_distribution, category_performance
    """
    try:
        logger.info(f"📊 Generating {viz_type} visualization...")
        
        # Get latest audit results
        audit_files = list(REPORTS_DIR.glob("audit_*.json")) + list(OUTPUTS_DIR.glob("audit_*.json"))
        if not audit_files:
            raise HTTPException(status_code=404, detail="No audit results available")
        
        latest_audit = sorted(audit_files)[-1]
        with open(latest_audit) as f:
            audit_data = json.load(f)
        
        # Initialize visualization service
        viz_service = VisualizationService(output_dir=str(REPORTS_DIR / "visualizations"))
        
        # Generate specific visualization
        viz_file = None
        company_name = audit_data.get("company_name", "Organization")
        
        if viz_type == "heatmap":
            viz_file = viz_service.generate_enhanced_heatmap(audit_data, company_name)
        elif viz_type == "gap_analysis":
            viz_file = viz_service.generate_gap_analysis_chart(audit_data)
        elif viz_type == "risk_distribution":
            viz_file = viz_service.generate_risk_distribution_chart(audit_data)
        elif viz_type == "category_performance":
            viz_file = viz_service.generate_category_performance_chart(audit_data)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown visualization type: {viz_type}")
        
        if not viz_file or not viz_file.exists():
            raise HTTPException(status_code=500, detail="Visualization generation failed")
        
        logger.info(f"✅ {viz_type} visualization generated: {viz_file}")
        
        return FileResponse(
            viz_file,
            media_type="image/png",
            filename=viz_file.name
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Visualization generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    import sys
    
    print("=" * 70)
    print("🚀 Starting Compliance AI Engine API...")
    print("=" * 70)
    print(f"📡 Backend: http://localhost:8000")
    print(f"📱 Frontend: http://localhost:5173")
    print(f"📖 API Docs: http://localhost:8000/docs")
    print(f"💚 Health Check: http://localhost:8000/health")
    print("=" * 70)
    print("Press Ctrl+C to stop the server")
    print("=" * 70)
    print()
    
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
            access_log=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Server failed to start: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)