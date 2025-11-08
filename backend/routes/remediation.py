import json
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from backend.services.remediation_service import RemediationService, Platform
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/scripts/{platform}")
async def generate_remediation_scripts(platform: str):
    """Generate remediation scripts for the specified platform."""
    try:
        platform_enum = Platform(platform.lower())
        remediation_service = RemediationService()
        
        # Generate scripts (this prepares the ZIP)
        zip_path = remediation_service.generate_remediation_scripts_zip(platform_enum)
        
        return {
            "status": "success",
            "message": f"Scripts generated for {platform}",
            "platform": platform,
            "zip_ready": True
        }
    except Exception as e:
        logger.error(f"Failed to generate scripts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scripts/{platform}/download")
async def download_remediation_scripts(platform: str):
    """Download remediation scripts as ZIP file."""
    try:
        platform_enum = Platform(platform.lower())
        remediation_service = RemediationService()
        
        zip_path = remediation_service.generate_remediation_scripts_zip(platform_enum)
        
        if not zip_path.exists():
            raise HTTPException(status_code=404, detail="Scripts not found")
        
        return FileResponse(
            path=zip_path,
            filename=f"remediation_scripts_{platform}.zip",
            media_type="application/zip"
        )
    except Exception as e:
        logger.error(f"Failed to download scripts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/guidance")
async def get_remediation_guidance():
    """Get remediation guidance for failed compliance checks."""
    try:
        # Check if we have any recent audit results
        reports_dir = Path("reports")
        json_reports_dir = reports_dir / "json"
        
        if not json_reports_dir.exists():
            return {
                "total_items": 0,
                "guidance": [],
                "message": "No audit results found. Please run a compliance scan first.",
                "timestamp": datetime.now().isoformat()
            }
        
        # Find the most recent audit result
        json_files = list(json_reports_dir.glob("*.json"))
        if not json_files:
            return {
                "total_items": 0,
                "guidance": [],
                "message": "No audit results found. Please run a compliance scan first.",
                "timestamp": datetime.now().isoformat()
            }
        
        # Get the most recent file
        latest_file = max(json_files, key=lambda x: x.stat().st_mtime)
        
        with open(latest_file, 'r') as f:
            audit_data = json.load(f)
        
        # Initialize remediation service
        remediation_service = RemediationService(output_dir=str(reports_dir / "remediation"))
        
        # Generate guidance for all failed rules
        all_guidance = []
        
        # Handle both audit JSON and frontend JSON structures
        frameworks = audit_data.get('frameworks', audit_data.get('framework_scores', {}))
        if not frameworks and 'audit_results' in audit_data:
            frameworks = audit_data['audit_results'].get('frameworks', {})
        
        for fw_name, fw_data in frameworks.items():
            # Extract rules from categories or directly
            rules = []
            if 'categories' in fw_data:
                for cat_name, cat_data in fw_data['categories'].items():
                    rules.extend(cat_data.get('rules', []))
            elif 'rules' in fw_data:
                rules = fw_data.get('rules', [])
            
            # Generate guidance for failed rules
            for rule in rules:
                status = rule.get('status', 'UNKNOWN')
                if status in ['FAIL', 'MISSING_DATA', 'ERROR', 'FAILED']:
                    try:
                        guidance = remediation_service.generate_remediation_guidance(rule, fw_name)
                        all_guidance.append({
                            'framework': fw_name,
                            'rule_id': rule.get('rule_id'),
                            'guidance': guidance.__dict__
                        })
                    except Exception as e:
                        logger.error(f"Error generating guidance for {rule.get('rule_id')}: {e}")
        
        return {
            "total_items": len(all_guidance),
            "guidance": all_guidance,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get remediation guidance: {e}")
        return {
            "total_items": 0,
            "guidance": [],
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }



