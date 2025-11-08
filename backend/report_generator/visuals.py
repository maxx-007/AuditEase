"""
Visualization Generation Module
===============================

Creates charts, heatmaps, and other visual assets for compliance reports.

Author: AuditEase Security Team
Version: 2.0.0
"""

import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10


class VisualizationGenerator:
    """Generates charts and visualizations for compliance reports."""
    
    def __init__(self, output_dir: Path):
        """
        Initialize visualization generator.
        
        Args:
            output_dir: Directory to save generated charts
        """
        self.output_dir = Path(output_dir)
        self.assets_dir = self.output_dir / "assets"
        self.assets_dir.mkdir(parents=True, exist_ok=True)
        
        # Color schemes
        self.colors = {
            'critical': '#8B0000',  # Dark red
            'high': '#DC2626',      # Red
            'medium': '#F59E0B',    # Orange
            'low': '#10B981',       # Green
            'info': '#3B82F6',      # Blue
            'gold': '#C9A961',      # Gold
            'burgundy': '#800020'   # Burgundy
        }
        
        self.status_colors = {
            'met': '#10B981',       # Green
            'partial': '#F59E0B',   # Orange
            'unmet': '#DC2626',     # Red
            'skipped': '#6B7280',   # Gray
            'error': '#8B0000'      # Dark red
        }
    
    def generate_framework_compliance_chart(
        self,
        framework_data: Dict[str, Any],
        filename: str = "framework_compliance.png"
    ) -> str:
        """
        Generate bar chart showing compliance scores per framework.
        
        Args:
            framework_data: Dictionary of framework summaries
            filename: Output filename
            
        Returns:
            Path to generated chart
        """
        try:
            frameworks = list(framework_data.keys())
            scores = [framework_data[fw].get('pass_rate', 0) for fw in frameworks]
            
            fig, ax = plt.subplots(figsize=(10, 6))
            
            bars = ax.bar(frameworks, scores, color=[self.colors['gold'], self.colors['burgundy'], self.colors['info']])
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}%',
                       ha='center', va='bottom', fontweight='bold')
            
            ax.set_ylabel('Compliance Score (%)', fontsize=12, fontweight='bold')
            ax.set_title('Framework Compliance Scores', fontsize=14, fontweight='bold')
            ax.set_ylim(0, 100)
            ax.grid(axis='y', alpha=0.3)
            
            plt.tight_layout()
            
            output_path = self.assets_dir / filename
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✓ Generated framework compliance chart: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating framework compliance chart: {e}")
            return ""
    
    def generate_category_heatmap(
        self,
        category_data: List[Dict[str, Any]],
        filename: str = "category_heatmap.png"
    ) -> str:
        """
        Generate heatmap showing compliance by category and framework.
        
        Args:
            category_data: List of category summaries
            filename: Output filename
            
        Returns:
            Path to generated chart
        """
        try:
            # Create pivot table
            df = pd.DataFrame(category_data)
            if df.empty:
                logger.warning("No category data for heatmap")
                return ""
            
            pivot = df.pivot_table(
                values='pass_rate',
                index='category',
                columns='framework',
                fill_value=0
            )
            
            fig, ax = plt.subplots(figsize=(12, 8))
            
            sns.heatmap(
                pivot,
                annot=True,
                fmt='.1f',
                cmap='RdYlGn',
                center=50,
                vmin=0,
                vmax=100,
                cbar_kws={'label': 'Compliance %'},
                ax=ax
            )
            
            ax.set_title('Compliance Heatmap by Category and Framework', fontsize=14, fontweight='bold')
            ax.set_xlabel('Framework', fontsize=12)
            ax.set_ylabel('Category', fontsize=12)
            
            plt.tight_layout()
            
            output_path = self.assets_dir / filename
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✓ Generated category heatmap: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating category heatmap: {e}")
            return ""
    
    def generate_severity_distribution(
        self,
        severity_counts: Dict[str, int],
        filename: str = "severity_distribution.png"
    ) -> str:
        """
        Generate pie chart showing severity distribution.
        
        Args:
            severity_counts: Dictionary of severity levels and counts
            filename: Output filename
            
        Returns:
            Path to generated chart
        """
        try:
            if not severity_counts or sum(severity_counts.values()) == 0:
                logger.warning("No severity data for distribution chart")
                return ""
            
            labels = list(severity_counts.keys())
            sizes = list(severity_counts.values())
            colors_list = [self.colors.get(label.lower(), '#6B7280') for label in labels]
            
            fig, ax = plt.subplots(figsize=(10, 8))
            
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors_list,
                autopct='%1.1f%%',
                startangle=90,
                textprops={'fontsize': 11, 'weight': 'bold'}
            )
            
            ax.set_title('Issue Severity Distribution', fontsize=14, fontweight='bold')
            
            plt.tight_layout()
            
            output_path = self.assets_dir / filename
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✓ Generated severity distribution chart: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating severity distribution: {e}")
            return ""
    
    def generate_status_donut_chart(
        self,
        status_counts: Dict[str, int],
        filename: str = "status_donut.png"
    ) -> str:
        """
        Generate donut chart showing rule status distribution.
        
        Args:
            status_counts: Dictionary of status types and counts
            filename: Output filename
            
        Returns:
            Path to generated chart
        """
        try:
            if not status_counts or sum(status_counts.values()) == 0:
                logger.warning("No status data for donut chart")
                return ""
            
            labels = list(status_counts.keys())
            sizes = list(status_counts.values())
            colors_list = [self.status_colors.get(label.lower(), '#6B7280') for label in labels]
            
            fig, ax = plt.subplots(figsize=(10, 8))
            
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors_list,
                autopct='%1.1f%%',
                startangle=90,
                pctdistance=0.85,
                textprops={'fontsize': 11, 'weight': 'bold'}
            )
            
            # Draw circle for donut effect
            centre_circle = plt.Circle((0, 0), 0.70, fc='white')
            ax.add_artist(centre_circle)
            
            ax.set_title('Rule Status Distribution', fontsize=14, fontweight='bold')
            
            plt.tight_layout()
            
            output_path = self.assets_dir / filename
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✓ Generated status donut chart: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating status donut chart: {e}")
            return ""
    
    def generate_trend_chart(
        self,
        trend_data: List[Dict[str, Any]],
        filename: str = "compliance_trend.png"
    ) -> str:
        """
        Generate line chart showing compliance trend over time.
        
        Args:
            trend_data: List of {date, score} dictionaries
            filename: Output filename
            
        Returns:
            Path to generated chart
        """
        try:
            if not trend_data or len(trend_data) < 2:
                logger.warning("Insufficient trend data for chart")
                return ""
            
            df = pd.DataFrame(trend_data)
            df['date'] = pd.to_datetime(df['date'])
            df = df.sort_values('date')
            
            fig, ax = plt.subplots(figsize=(12, 6))
            
            ax.plot(df['date'], df['score'], marker='o', linewidth=2, markersize=8, color=self.colors['gold'])
            ax.fill_between(df['date'], df['score'], alpha=0.3, color=self.colors['gold'])
            
            ax.set_xlabel('Date', fontsize=12, fontweight='bold')
            ax.set_ylabel('Compliance Score (%)', fontsize=12, fontweight='bold')
            ax.set_title('Compliance Trend Over Time', fontsize=14, fontweight='bold')
            ax.grid(True, alpha=0.3)
            ax.set_ylim(0, 100)
            
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            output_path = self.assets_dir / filename
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✓ Generated trend chart: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating trend chart: {e}")
            return ""

