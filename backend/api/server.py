"""
FastAPI Server for Compliance AI Engine
========================================
REST API endpoints for frontend integration.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from typing import Dict, Any, Optional, List
from pathlib import Path
import json
import yaml
from datetime import datetime
import os

from utils.logger import setup_logger

logger = setup_logger("api_server")


def create_app(orchestrator=None):
    """Create and configure FastAPI application."""
    
    # Load config for CORS settings
    config_path = Path(__file__).parent.parent / "config.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    app = FastAPI(
        title="Compliance AI Engine API",
        description="Enterprise Compliance Automation System API",
        version="1.0.0"
    )
    
    # Configure CORS
    cors_origins = config.get('api', {}).get('cors_origins', [
        "http://localhost:3000",
        "http://localhost:5173"
    ])
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Store orchestrator instance
    app.state.orchestrator = orchestrator
    
    # ============= COMPLIANCE ENDPOINTS =============
    
    @app.get("/api/compliance/summary")
    async def get_compliance_summary():
        """Get compliance summary for dashboard."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            # Try to get latest audit results
            reports_dir = orchestrator.reports_dir / "json"
            result_files = list(reports_dir.glob("frontend_*.json"))
            
            if result_files:
                # Get latest file
                latest_file = max(result_files, key=lambda f: f.stat().st_mtime)
                with open(latest_file) as f:
                    data = json.load(f)
                return data
            
            # Return default structure if no reports exist
            return {
                "score": 0,
                "riskLevel": "Unknown",
                "validControls": 0,
                "gaps": 0,
                "trend": [],
                "categories": [],
                "distribution": [],
                "remediation": []
            }
        except Exception as e:
            logger.error(f"Error fetching compliance summary: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/compliance/report")
    async def get_compliance_report():
        """Get full compliance report."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            reports_dir = orchestrator.reports_dir / "json"
            result_files = list(reports_dir.glob("audit_*.json"))
            
            if result_files:
                latest_file = max(result_files, key=lambda f: f.stat().st_mtime)
                with open(latest_file) as f:
                    return json.load(f)
            
            raise HTTPException(status_code=404, detail="No compliance reports found")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error fetching compliance report: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/compliance/remediation")
    async def get_compliance_remediation():
        """Get remediation recommendations."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            reports_dir = orchestrator.reports_dir / "json"
            result_files = list(reports_dir.glob("frontend_*.json"))
            
            if result_files:
                latest_file = max(result_files, key=lambda f: f.stat().st_mtime)
                with open(latest_file) as f:
                    data = json.load(f)
                    return {
                        "remediation": data.get("remediation", [])
                    }
            
            return {"remediation": []}
        except Exception as e:
            logger.error(f"Error fetching remediation: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/compliance/train")
    async def train_model(data: Dict[str, Any]):
        """Train ML model with provided dataset."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            dataset_path = data.get("dataset_path")
            algorithm = data.get("algorithm", "RandomForest")
            
            if not dataset_path:
                raise HTTPException(status_code=400, detail="dataset_path is required")
            
            result = orchestrator.train_pipeline(dataset_path, algorithm)
            
            if result.get("success"):
                return result
            else:
                raise HTTPException(status_code=500, detail=result.get("error", "Training failed"))
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error training model: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/compliance/collect")
    async def collect_data(data: Dict[str, Any]):
        """Collect compliance data."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            realtime = data.get("realtime", False)
            interval = data.get("interval", 300)
            output_path = data.get("output_path")
            
            result = orchestrator.collect_pipeline(
                realtime=realtime,
                interval=interval,
                output_path=output_path
            )
            
            if result.get("success"):
                return result
            else:
                raise HTTPException(status_code=500, detail=result.get("error", "Collection failed"))
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error collecting data: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/compliance/infer")
    async def run_inference(data: Dict[str, Any]):
        """Run ML inference on compliance data."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            # Get ML service and run prediction
            ml_prediction = orchestrator.ml_service.predict(data)
            
            return {
                "success": True,
                "prediction": ml_prediction
            }
        except Exception as e:
            logger.error(f"Error running inference: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    # ============= AUDIT ENDPOINTS =============
    
    @app.get("/api/audit/report")
    async def get_audit_report():
        """Get audit report."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            reports_dir = orchestrator.reports_dir / "json"
            result_files = list(reports_dir.glob("audit_*.json"))
            
            if result_files:
                latest_file = max(result_files, key=lambda f: f.stat().st_mtime)
                with open(latest_file) as f:
                    return json.load(f)
            
            raise HTTPException(status_code=404, detail="No audit reports found")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error fetching audit report: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/audit/remediation")
    async def get_audit_remediation():
        """Get audit remediation recommendations."""
        return await get_compliance_remediation()
    
    # ============= REPORT ENDPOINTS =============
    
    @app.post("/api/reports/generate")
    async def generate_report(filters: Dict[str, Any]):
        """Generate compliance reports."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            company = filters.get("company")
            latest = filters.get("latest", True)
            
            result = orchestrator.report_pipeline(company=company, latest=latest)
            
            if result.get("success"):
                return result
            else:
                raise HTTPException(status_code=500, detail=result.get("error", "Report generation failed"))
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error generating report: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/reports/{report_id}/download/pdf")
    async def download_report_pdf(report_id: str):
        """Download PDF report."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            reports_dir = orchestrator.reports_dir / "pdf"
            pdf_files = list(reports_dir.glob("*.pdf"))
            
            if pdf_files:
                # Try to find by ID or get latest
                if report_id != "latest":
                    matching = [f for f in pdf_files if report_id in f.stem]
                    if matching:
                        return FileResponse(matching[0], media_type="application/pdf")
                
                # Return latest
                latest_file = max(pdf_files, key=lambda f: f.stat().st_mtime)
                return FileResponse(latest_file, media_type="application/pdf")
            
            raise HTTPException(status_code=404, detail="PDF report not found")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error downloading PDF: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/reports/{report_id}/download/excel")
    async def download_report_excel(report_id: str):
        """Download Excel report."""
        try:
            if not orchestrator:
                raise HTTPException(status_code=500, detail="Orchestrator not initialized")
            
            reports_dir = orchestrator.reports_dir / "excel"
            excel_files = list(reports_dir.glob("*.xlsx"))
            
            if excel_files:
                if report_id != "latest":
                    matching = [f for f in excel_files if report_id in f.stem]
                    if matching:
                        return FileResponse(matching[0], media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                
                latest_file = max(excel_files, key=lambda f: f.stat().st_mtime)
                return FileResponse(latest_file, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            
            raise HTTPException(status_code=404, detail="Excel report not found")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error downloading Excel: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/reports/{report_id}/remediation")
    async def download_remediation_script(report_id: str):
        """Download remediation script."""
        try:
            # For now, return a placeholder
            # In production, this would generate and return a shell script
            script_content = "#!/bin/bash\n# Remediation script\n# Generated by Compliance AI Engine\n"
            
            return JSONResponse(
                content={"script": script_content},
                headers={"Content-Disposition": f'attachment; filename="remediation_{report_id}.sh"'}
            )
        except Exception as e:
            logger.error(f"Error generating remediation script: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    
    # ============= HEALTH CHECK =============
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "Compliance AI Engine API",
            "version": "1.0.0"
        }
    
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "message": "Compliance AI Engine API",
            "version": "1.0.0",
            "docs": "/docs"
        }
    
    return app

