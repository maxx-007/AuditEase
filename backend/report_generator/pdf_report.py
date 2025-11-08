"""
PDF Report Generator Module
===========================

Generates comprehensive PDF reports with charts, heatmaps, and detailed analysis.

Author: AuditEase Security Team
Version: 2.0.0
"""

import logging
from pathlib import Path
from typing import Dict, Any
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.enhanced_pdf_service import EnhancedPDFService

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """
    PDF report generator - wraps EnhancedPDFService.
    
    This class provides a consistent interface for the report generator
    while leveraging the existing comprehensive PDF generation service.
    """
    
    def __init__(self, output_dir: Path):
        """
        Initialize PDF generator.
        
        Args:
            output_dir: Directory to save PDF files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.service = EnhancedPDFService(output_dir=str(self.output_dir))
    
    def generate_pdf_report(
        self,
        report_data: Dict[str, Any],
        filename: str = "compliance_report.pdf"
    ) -> str:
        """
        Generate comprehensive PDF report.
        
        Args:
            report_data: Complete report data dictionary
            filename: Output filename
            
        Returns:
            Path to generated PDF file
        """
        try:
            logger.info(f"📄 Generating PDF report: {filename}")
            
            # Extract company name from metadata
            company_name = report_data.get('metadata', {}).get('company_name', 'Organization')
            
            # Use the enhanced PDF service
            pdf_path = self.service.generate_comprehensive_pdf(
                audit_results=report_data,
                company_name=company_name
            )
            
            logger.info(f"✓ PDF report generated: {pdf_path}")
            return pdf_path
            
        except Exception as e:
            logger.error(f"❌ PDF generation failed: {e}", exc_info=True)
            raise

