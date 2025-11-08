#!/usr/bin/env python3
"""
Visualization Service - Production-Grade Interactive Visualization Module
=========================================================================
Provides interactive dashboards, trend analysis, and advanced visualizations
using Plotly, Matplotlib, and Seaborn.

Features:
- Interactive Plotly dashboards (HTML)
- Enhanced compliance heatmaps
- Trend analysis with historical data
- Gap analysis visualizations
- Risk distribution charts
- Category performance analysis
- Framework comparison radar charts
- Export to PNG, SVG, HTML formats
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import json
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64

# Setup logger
logger = logging.getLogger(__name__)


class VisualizationService:
    """
    Production-grade visualization service for compliance data.
    
    Generates interactive dashboards, trend analysis, and advanced
    visualizations for compliance audit results.
    """
    
    def __init__(self, output_dir: str = "visualizations"):
        """
        Initialize the Visualization Service.
        
        Args:
            output_dir: Directory to save generated visualizations
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Set professional style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 10
        
        # Color schemes
        self.colors = {
            'primary': '#1F4E79',
            'secondary': '#4472C4',
            'success': '#00CC00',
            'warning': '#FFA500',
            'danger': '#FF0000',
            'critical': '#8B0000',
        }
        
        self.risk_colors = {
            'CRITICAL': self.colors['critical'],
            'HIGH': self.colors['danger'],
            'MEDIUM': self.colors['warning'],
            'LOW': self.colors['success'],
            'EXCELLENT': '#00CC00'
        }
        
        logger.info(f"Visualization Service initialized - Output: {self.output_dir}")
    
    def generate_interactive_dashboard(
        self,
        audit_results: Dict[str, Any],
        company_name: str = "Organization"
    ) -> Path:
        """
        Generate comprehensive interactive dashboard using Plotly.
        
        Args:
            audit_results: Complete audit results
            company_name: Name of the organization
            
        Returns:
            Path to generated HTML dashboard
        """
        try:
            logger.info(f"Generating interactive dashboard for {company_name}...")
            
            # Create subplots
            fig = make_subplots(
                rows=3, cols=2,
                subplot_titles=(
                    'Compliance Overview',
                    'Risk Distribution',
                    'Framework Comparison',
                    'Category Performance',
                    'Severity Analysis',
                    'Compliance Trend'
                ),
                specs=[
                    [{"type": "bar"}, {"type": "pie"}],
                    [{"type": "bar"}, {"type": "heatmap"}],
                    [{"type": "bar"}, {"type": "scatter"}]
                ],
                vertical_spacing=0.12,
                horizontal_spacing=0.15
            )
            
            frameworks = audit_results.get('frameworks', {})
            
            # 1. Compliance Overview (Bar Chart)
            fw_names = list(frameworks.keys())
            fw_scores = [
                frameworks[fw].get('overall', frameworks[fw]).get('compliance_percentage', 0)
                for fw in fw_names
            ]
            
            fig.add_trace(
                go.Bar(
                    x=fw_names,
                    y=fw_scores,
                    name="Compliance %",
                    marker_color=self.colors['primary'],
                    text=[f"{score:.1f}%" for score in fw_scores],
                    textposition='auto'
                ),
                row=1, col=1
            )
            
            # 2. Risk Distribution (Pie Chart)
            risk_counts = {}
            for fw_data in frameworks.values():
                risk_level = fw_data.get('overall', fw_data).get('risk_level', 'UNKNOWN')
                risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
            
            fig.add_trace(
                go.Pie(
                    labels=list(risk_counts.keys()),
                    values=list(risk_counts.values()),
                    marker_colors=[self.risk_colors.get(level, '#999999') for level in risk_counts.keys()],
                    hole=0.3
                ),
                row=1, col=2
            )
            
            # 3. Framework Comparison (Grouped Bar)
            passed_rules = [
                frameworks[fw].get('overall', frameworks[fw]).get('passed_rules', 0)
                for fw in fw_names
            ]
            failed_rules = [
                frameworks[fw].get('overall', frameworks[fw]).get('failed_rules', 0)
                for fw in fw_names
            ]
            
            fig.add_trace(
                go.Bar(name='Passed', x=fw_names, y=passed_rules, marker_color=self.colors['success']),
                row=2, col=1
            )
            fig.add_trace(
                go.Bar(name='Failed', x=fw_names, y=failed_rules, marker_color=self.colors['danger']),
                row=2, col=1
            )
            
            # 4. Category Performance (Heatmap)
            category_data = []
            categories = set()
            for fw_name, fw_data in frameworks.items():
                cat_scores = fw_data.get('category_scores', fw_data.get('category_breakdown', {}))
                for cat, stats in cat_scores.items():
                    categories.add(cat)
                    category_data.append({
                        'Framework': fw_name,
                        'Category': cat,
                        'Score': stats.get('compliance_percentage', stats.get('compliance_pct', 0))
                    })
            
            if category_data:
                df_cat = pd.DataFrame(category_data)
                pivot = df_cat.pivot(index='Category', columns='Framework', values='Score')
                
                fig.add_trace(
                    go.Heatmap(
                        z=pivot.values,
                        x=pivot.columns.tolist(),
                        y=pivot.index.tolist(),
                        colorscale='RdYlGn',
                        text=pivot.values,
                        texttemplate='%{text:.1f}%',
                        textfont={"size": 10},
                        colorbar=dict(title="Compliance %")
                    ),
                    row=2, col=2
                )
            
            # 5. Severity Analysis (Stacked Bar)
            severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            for severity in severities:
                counts = [
                    frameworks[fw].get('overall', frameworks[fw]).get('severity_breakdown', {}).get(severity, 0)
                    for fw in fw_names
                ]
                fig.add_trace(
                    go.Bar(
                        name=severity,
                        x=fw_names,
                        y=counts,
                        marker_color=self.risk_colors.get(severity, '#999999')
                    ),
                    row=3, col=1
                )
            
            # 6. Compliance Trend (Line - placeholder with current data)
            fig.add_trace(
                go.Scatter(
                    x=['Current'],
                    y=[audit_results.get('overall_summary', {}).get('average_compliance_percentage', 0)],
                    mode='lines+markers',
                    name='Overall Compliance',
                    line=dict(color=self.colors['primary'], width=3),
                    marker=dict(size=10)
                ),
                row=3, col=2
            )
            
            # Update layout
            fig.update_layout(
                title_text=f"<b>{company_name} - Compliance Dashboard</b>",
                title_x=0.5,
                title_font=dict(size=20),
                showlegend=True,
                height=1200,
                template="plotly_white"
            )
            
            # Update axes
            fig.update_xaxes(title_text="Framework", row=1, col=1)
            fig.update_yaxes(title_text="Compliance %", row=1, col=1)
            fig.update_xaxes(title_text="Framework", row=2, col=1)
            fig.update_yaxes(title_text="Rule Count", row=2, col=1)
            fig.update_xaxes(title_text="Framework", row=3, col=1)
            fig.update_yaxes(title_text="Issue Count", row=3, col=1)
            
            # Save dashboard
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dashboard_file = self.output_dir / f"interactive_dashboard_{company_name}_{timestamp}.html"
            fig.write_html(str(dashboard_file))
            
            logger.info(f"✅ Interactive dashboard generated: {dashboard_file}")
            return dashboard_file
            
        except Exception as e:
            logger.error(f"Error generating dashboard: {e}", exc_info=True)
            raise
    
    def generate_enhanced_heatmap(
        self,
        audit_results: Dict[str, Any],
        company_name: str = "Organization"
    ) -> Path:
        """
        Generate enhanced compliance heatmap.
        
        Args:
            audit_results: Complete audit results
            company_name: Name of the organization
            
        Returns:
            Path to generated heatmap image
        """
        try:
            logger.info("Generating enhanced compliance heatmap...")
            
            frameworks = audit_results.get('frameworks', {})
            
            # Prepare data
            data = []
            for fw_name, fw_data in frameworks.items():
                overall = fw_data.get('overall', fw_data)
                data.append({
                    'Framework': fw_name,
                    'Compliance': overall.get('compliance_percentage', 0),
                    'Risk': overall.get('risk_level', 'UNKNOWN')
                })
            
            df = pd.DataFrame(data)
            
            # Create figure
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Create heatmap
            pivot = df.pivot_table(values='Compliance', index='Framework', aggfunc='first')
            sns.heatmap(
                pivot,
                annot=True,
                fmt='.1f',
                cmap='RdYlGn',
                cbar_kws={'label': 'Compliance %'},
                vmin=0,
                vmax=100,
                ax=ax
            )
            
            ax.set_title(f'{company_name} - Compliance Heatmap', fontsize=16, fontweight='bold')
            ax.set_xlabel('', fontsize=12)
            ax.set_ylabel('Framework', fontsize=12)
            
            plt.tight_layout()
            
            # Save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            heatmap_file = self.output_dir / f"compliance_heatmap_{company_name}_{timestamp}.png"
            plt.savefig(heatmap_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✅ Enhanced heatmap generated: {heatmap_file}")
            return heatmap_file
            
        except Exception as e:
            logger.error(f"Error generating heatmap: {e}", exc_info=True)
            raise
    
    def generate_gap_analysis_chart(
        self,
        audit_results: Dict[str, Any],
        target_compliance: float = 85.0
    ) -> Path:
        """
        Generate gap analysis visualization.
        
        Args:
            audit_results: Complete audit results
            target_compliance: Target compliance percentage
            
        Returns:
            Path to generated gap analysis chart
        """
        try:
            logger.info("Generating gap analysis chart...")
            
            frameworks = audit_results.get('frameworks', {})
            
            # Prepare data
            gap_data = []
            for fw_name, fw_data in frameworks.items():
                current = fw_data.get('overall', fw_data).get('compliance_percentage', 0)
                gap = max(0, target_compliance - current)
                
                gap_data.append({
                    'Framework': fw_name,
                    'Current': current,
                    'Gap': gap,
                    'Target': target_compliance
                })
            
            df = pd.DataFrame(gap_data)
            
            # Create figure
            fig, ax = plt.subplots(figsize=(12, 6))
            
            x = np.arange(len(df))
            width = 0.35
            
            # Plot bars
            bars1 = ax.bar(x - width/2, df['Current'], width, label='Current', color=self.colors['primary'])
            bars2 = ax.bar(x + width/2, df['Gap'], width, label='Gap to Target', color=self.colors['danger'])
            
            # Add target line
            ax.axhline(y=target_compliance, color=self.colors['success'], linestyle='--', label=f'Target ({target_compliance}%)')
            
            # Customize
            ax.set_xlabel('Framework', fontsize=12, fontweight='bold')
            ax.set_ylabel('Compliance %', fontsize=12, fontweight='bold')
            ax.set_title('Compliance Gap Analysis', fontsize=16, fontweight='bold')
            ax.set_xticks(x)
            ax.set_xticklabels(df['Framework'])
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # Add value labels
            for bar in bars1:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}%', ha='center', va='bottom', fontsize=9)
            
            plt.tight_layout()
            
            # Save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            gap_file = self.output_dir / f"gap_analysis_{timestamp}.png"
            plt.savefig(gap_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✅ Gap analysis chart generated: {gap_file}")
            return gap_file
            
        except Exception as e:
            logger.error(f"Error generating gap analysis: {e}", exc_info=True)
            raise
    
    def generate_risk_distribution_chart(
        self,
        audit_results: Dict[str, Any]
    ) -> Path:
        """
        Generate risk distribution visualization.
        
        Args:
            audit_results: Complete audit results
            
        Returns:
            Path to generated risk distribution chart
        """
        try:
            logger.info("Generating risk distribution chart...")
            
            frameworks = audit_results.get('frameworks', {})
            
            # Collect severity data
            severity_data = []
            for fw_name, fw_data in frameworks.items():
                severity_breakdown = fw_data.get('overall', fw_data).get('severity_breakdown', {})
                for severity, count in severity_breakdown.items():
                    if count > 0:
                        severity_data.append({
                            'Framework': fw_name,
                            'Severity': severity,
                            'Count': count
                        })
            
            if not severity_data:
                logger.warning("No severity data available for risk distribution")
                return None
            
            df = pd.DataFrame(severity_data)
            
            # Create figure with subplots
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
            
            # 1. Stacked bar chart by framework
            pivot = df.pivot_table(values='Count', index='Framework', columns='Severity', fill_value=0)
            pivot = pivot[['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']] if all(col in pivot.columns for col in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) else pivot
            
            pivot.plot(
                kind='bar',
                stacked=True,
                ax=ax1,
                color=[self.risk_colors.get(col, '#999999') for col in pivot.columns]
            )
            ax1.set_title('Risk Distribution by Framework', fontsize=14, fontweight='bold')
            ax1.set_xlabel('Framework', fontsize=12)
            ax1.set_ylabel('Issue Count', fontsize=12)
            ax1.legend(title='Severity')
            ax1.grid(True, alpha=0.3)
            
            # 2. Overall severity pie chart
            total_by_severity = df.groupby('Severity')['Count'].sum()
            colors = [self.risk_colors.get(sev, '#999999') for sev in total_by_severity.index]
            
            wedges, texts, autotexts = ax2.pie(
                total_by_severity.values,
                labels=total_by_severity.index,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90
            )
            ax2.set_title('Overall Severity Distribution', fontsize=14, fontweight='bold')
            
            plt.tight_layout()
            
            # Save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            risk_file = self.output_dir / f"risk_distribution_{timestamp}.png"
            plt.savefig(risk_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✅ Risk distribution chart generated: {risk_file}")
            return risk_file
            
        except Exception as e:
            logger.error(f"Error generating risk distribution: {e}", exc_info=True)
            raise
    
    def generate_category_performance_chart(
        self,
        audit_results: Dict[str, Any]
    ) -> Path:
        """
        Generate category performance visualization.
        
        Args:
            audit_results: Complete audit results
            
        Returns:
            Path to generated category performance chart
        """
        try:
            logger.info("Generating category performance chart...")
            
            frameworks = audit_results.get('frameworks', {})
            
            # Collect category data
            category_data = []
            for fw_name, fw_data in frameworks.items():
                categories = fw_data.get('category_scores', fw_data.get('category_breakdown', {}))
                for cat, stats in categories.items():
                    category_data.append({
                        'Framework': fw_name,
                        'Category': cat,
                        'Compliance': stats.get('compliance_percentage', stats.get('compliance_pct', 0))
                    })
            
            if not category_data:
                logger.warning("No category data available")
                return None
            
            df = pd.DataFrame(category_data)
            
            # Calculate average by category
            avg_by_category = df.groupby('Category')['Compliance'].mean().sort_values()
            
            # Create figure
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Horizontal bar chart
            bars = ax.barh(range(len(avg_by_category)), avg_by_category.values)
            
            # Color code based on performance
            for i, (bar, val) in enumerate(zip(bars, avg_by_category.values)):
                if val >= 85:
                    bar.set_color(self.colors['success'])
                elif val >= 60:
                    bar.set_color(self.colors['warning'])
                else:
                    bar.set_color(self.colors['danger'])
                
                # Add value labels
                ax.text(val + 1, i, f'{val:.1f}%', va='center', fontsize=9)
            
            ax.set_yticks(range(len(avg_by_category)))
            ax.set_yticklabels(avg_by_category.index)
            ax.set_xlabel('Average Compliance %', fontsize=12, fontweight='bold')
            ax.set_title('Category Performance Analysis', fontsize=16, fontweight='bold')
            ax.grid(True, alpha=0.3, axis='x')
            
            plt.tight_layout()
            
            # Save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            category_file = self.output_dir / f"category_performance_{timestamp}.png"
            plt.savefig(category_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"✅ Category performance chart generated: {category_file}")
            return category_file
            
        except Exception as e:
            logger.error(f"Error generating category performance: {e}", exc_info=True)
            raise
    
    def generate_all_visualizations(
        self,
        audit_results: Dict[str, Any],
        company_name: str = "Organization"
    ) -> Dict[str, Path]:
        """
        Generate all visualizations at once.
        
        Args:
            audit_results: Complete audit results
            company_name: Name of the organization
            
        Returns:
            Dictionary mapping visualization type to file path
        """
        try:
            logger.info("Generating all visualizations...")
            
            visualizations = {}
            
            # Generate each visualization
            try:
                visualizations['dashboard'] = self.generate_interactive_dashboard(audit_results, company_name)
            except Exception as e:
                logger.error(f"Dashboard generation failed: {e}")
            
            try:
                visualizations['heatmap'] = self.generate_enhanced_heatmap(audit_results, company_name)
            except Exception as e:
                logger.error(f"Heatmap generation failed: {e}")
            
            try:
                visualizations['gap_analysis'] = self.generate_gap_analysis_chart(audit_results)
            except Exception as e:
                logger.error(f"Gap analysis generation failed: {e}")
            
            try:
                visualizations['risk_distribution'] = self.generate_risk_distribution_chart(audit_results)
            except Exception as e:
                logger.error(f"Risk distribution generation failed: {e}")
            
            try:
                visualizations['category_performance'] = self.generate_category_performance_chart(audit_results)
            except Exception as e:
                logger.error(f"Category performance generation failed: {e}")
            
            logger.info(f"✅ Generated {len(visualizations)} visualizations")
            return visualizations
            
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}", exc_info=True)
            raise


# Export main class
__all__ = ['VisualizationService']

