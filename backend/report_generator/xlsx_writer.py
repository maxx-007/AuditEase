"""
Excel Report Writer Module
==========================

Generates comprehensive Excel workbooks with multiple sheets, charts, and formatting.

Author: AuditEase Security Team
Version: 2.0.0
"""

import logging
from pathlib import Path
from typing import Dict, Any, List
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.ultra_comprehensive_report_service import UltraComprehensiveReportService

logger = logging.getLogger(__name__)


class ExcelReportWriter:
    """
    Excel report writer - wraps UltraComprehensiveReportService.
    
    This class provides a consistent interface for the report generator
    while leveraging the existing comprehensive Excel generation service.
    """
    
    def __init__(self, output_dir: Path):
        """
        Initialize Excel writer.
        
        Args:
            output_dir: Directory to save Excel files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.service = UltraComprehensiveReportService(output_dir=str(self.output_dir))
    
    def generate_excel_report(
        self,
        report_data: Dict[str, Any],
        filename: str = "compliance_report.xlsx"
    ) -> str:
        """
        Generate comprehensive Excel report.
        
        Args:
            report_data: Complete report data dictionary
            filename: Output filename
            
        Returns:
            Path to generated Excel file
        """
        try:
            logger.info(f"📊 Generating Excel report: {filename}")
            
            # Extract company name from metadata
            company_name = report_data.get('metadata', {}).get('company_name', 'Organization')
            
            # Use the ultra comprehensive service
            excel_path = self.service.generate_ultra_comprehensive_excel(
                audit_results=report_data,
                system_name=company_name
            )
            
            logger.info(f"✓ Excel report generated: {excel_path}")
            return excel_path
            
        except Exception as e:
            logger.error(f"❌ Excel generation failed: {e}", exc_info=True)
            raise

