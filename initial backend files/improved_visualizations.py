#!/usr/bin/env python3
"""
Improved Visualization Components for Compliance Audit Engine
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from pathlib import Path
import matplotlib.dates as mdates
from matplotlib.colors import LinearSegmentedColormap

# Set style for all matplotlib visualizations
plt.style.use('ggplot')
sns.set_style("whitegrid")
sns.set_context("talk")

# Define color schemes
RISK_COLORS = {
    'CRITICAL': '#8B0000',  # Dark red
    'HIGH': '#FF4444',      # Red
    'MEDIUM': '#FFA500',    # Orange
    'LOW': '#FFD700',       # Yellow
    'EXCELLENT': '#4CAF50'  # Green
}

# Custom color maps
risk_cmap = LinearSegmentedColormap.from_list(
    'risk_cmap', ['#8B0000', '#FF4444', '#FFA500', '#FFD700', '#4CAF50'], N=100
)

def generate_improved_trend_analysis(historical_data_dir, output_dir, timestamp=None):
    """
    Generate improved trend analysis visualization that is clearer and easier to understand
    
    Args:
        historical_data_dir: Directory containing historical audit data
        output_dir: Directory to save the output visualization
        timestamp: Optional timestamp for the output file
    
    Returns:
        Path to the generated visualization file
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Load historical data
    historical_files = list(Path(historical_data_dir).glob("audit_*.json"))
    if len(historical_files) < 1:
        print("Insufficient historical data for trend analysis")
        return None
    
    # Process historical data
    trend_data = []
    for file_path in sorted(historical_files):
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Extract timestamp
        if 'metadata' in data and 'timestamp' in data['metadata']:
            timestamp_str = data['metadata']['timestamp']
        else:
            # Try to extract from filename
            timestamp_str = file_path.stem.replace('audit_', '')
        
        try:
            timestamp_dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
        except ValueError:
            # If timestamp format is different, use file modification time
            timestamp_dt = datetime.fromtimestamp(file_path.stat().st_mtime)
        
        # Extract compliance data
        for company, frameworks in data.get('results', {}).items():
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    trend_data.append({
                        'date': timestamp_dt,
                        'company': company,
                        'framework': framework,
                        'compliance_percentage': metrics.get('compliance_percentage', 0),
                        'risk_level': metrics.get('risk_level', 'CRITICAL'),
                        'passed_rules': metrics.get('passed_rules', 0),
                        'total_rules': metrics.get('total_rules', 0),
                        'pass_rate': metrics.get('passed_rules', 0) / metrics.get('total_rules', 1) * 100
                    })
    
    if not trend_data:
        print("No trend data found in historical files")
        return None
    
    # Convert to DataFrame for easier manipulation
    df_trend = pd.DataFrame(trend_data)
    
    # Sort by date to ensure chronological order
    df_trend = df_trend.sort_values('date')
    
    # Create figure with subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 12), gridspec_kw={'height_ratios': [2, 1]})
    
    # 1. Main Trend Plot - Clear and Focused
    companies = df_trend['company'].unique()
    frameworks = df_trend['framework'].unique()
    
    # Create a color palette for companies
    company_colors = sns.color_palette("husl", len(companies))
    company_color_map = {company: company_colors[i] for i, company in enumerate(companies)}
    
    # Create line styles for frameworks
    framework_styles = ['-', '--', '-.', ':']
    framework_style_map = {framework: framework_styles[i % len(framework_styles)] 
                          for i, framework in enumerate(frameworks)}
    
    # Plot each company-framework combination
    for company in companies:
        for framework in frameworks:
            subset = df_trend[(df_trend['company'] == company) & (df_trend['framework'] == framework)]
            if not subset.empty:
                ax1.plot(subset['date'], subset['compliance_percentage'], 
                        linestyle=framework_style_map[framework],
                        color=company_color_map[company],
                        marker='o', markersize=8, linewidth=2.5,
                        label=f"{company} - {framework}")
    
    # Add reference lines for risk levels
    risk_levels = [
        ('CRITICAL', 25, '#8B0000'),
        ('HIGH', 50, '#FF4444'),
        ('MEDIUM', 75, '#FFA500'),
        ('LOW', 85, '#FFD700'),
        ('EXCELLENT', 100, '#4CAF50')
    ]
    
    for level, threshold, color in risk_levels:
        ax1.axhline(y=threshold, color=color, linestyle='--', alpha=0.5)
        ax1.text(df_trend['date'].min(), threshold + 1, level, 
                color=color, fontweight='bold', va='bottom')
    
    # Customize the main trend plot
    ax1.set_title('Compliance Trend Analysis Over Time', fontsize=20, fontweight='bold', pad=20)
    ax1.set_ylabel('Compliance Percentage (%)', fontsize=14, fontweight='bold')
    ax1.set_ylim(0, 105)  # Give some space at the top for labels
    
    # Format x-axis to show dates clearly
    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    ax1.xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    # Add grid for better readability
    ax1.grid(True, alpha=0.3)
    
    # Add legend with clear organization
    handles, labels = ax1.get_legend_handles_labels()
    ax1.legend(handles, labels, loc='upper left', bbox_to_anchor=(1.01, 1), 
              fontsize=12, frameon=True, facecolor='white', edgecolor='gray')
    
    # 2. Improvement/Deterioration Analysis
    if len(df_trend['date'].unique()) >= 2:
        # Get the two most recent dates
        dates = sorted(df_trend['date'].unique())
        latest_date = dates[-1]
        previous_date = dates[-2] if len(dates) > 1 else dates[0]
        
        # Calculate changes between the two dates
        changes = []
        for company in companies:
            for framework in frameworks:
                latest = df_trend[(df_trend['company'] == company) & 
                                 (df_trend['framework'] == framework) & 
                                 (df_trend['date'] == latest_date)]
                
                previous = df_trend[(df_trend['company'] == company) & 
                                   (df_trend['framework'] == framework) & 
                                   (df_trend['date'] == previous_date)]
                
                if not latest.empty and not previous.empty:
                    change = latest['compliance_percentage'].values[0] - previous['compliance_percentage'].values[0]
                    changes.append({
                        'company': company,
                        'framework': framework,
                        'change': change,
                        'latest': latest['compliance_percentage'].values[0],
                        'previous': previous['compliance_percentage'].values[0]
                    })
        
        if changes:
            # Convert to DataFrame and sort
            df_changes = pd.DataFrame(changes).sort_values('change')
            
            # Create labels for the bars
            labels = [f"{row['company']} - {row['framework']}" for _, row in df_changes.iterrows()]
            
            # Plot horizontal bars with color based on change direction
            bars = ax2.barh(range(len(df_changes)), df_changes['change'], 
                           color=['#FF4444' if x < 0 else '#4CAF50' for x in df_changes['change']])
            
            # Add value labels to the bars
            for i, (bar, val) in enumerate(zip(bars, df_changes['change'])):
                text_color = 'white' if abs(val) > 10 else 'black'
                ax2.text(val + (0.5 if val >= 0 else -0.5), i, f"{val:+.1f}%", 
                        va='center', ha='left' if val >= 0 else 'right',
                        color=text_color, fontweight='bold')
            
            # Add latest and previous values
            for i, (_, row) in enumerate(df_changes.iterrows()):
                ax2.text(0, i, f"{row['previous']:.1f}% → {row['latest']:.1f}%", 
                        va='center', ha='center', fontsize=9,
                        bbox=dict(facecolor='white', alpha=0.7, boxstyle='round,pad=0.3'))
            
            # Customize the change analysis plot
            ax2.set_yticks(range(len(df_changes)))
            ax2.set_yticklabels(labels)
            ax2.set_xlabel('Change in Compliance Percentage (%)', fontsize=14, fontweight='bold')
            ax2.set_title(f'Compliance Change: {previous_date.strftime("%Y-%m-%d")} to {latest_date.strftime("%Y-%m-%d")}', 
                         fontsize=16, fontweight='bold')
            
            # Add a vertical line at x=0
            ax2.axvline(x=0, color='black', linestyle='-', alpha=0.5)
            
            # Add grid for better readability
            ax2.grid(True, axis='x', alpha=0.3)
    
    # Add overall title and adjust layout
    plt.suptitle('Enhanced Compliance Trend Analysis', fontsize=24, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0, 0.85, 0.95])  # Make room for the legend
    
    # Save the figure
    output_file = output_path / f"improved_trend_analysis_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print(f"Improved trend analysis saved to: {output_file}")
    return output_file

def generate_interactive_trend_dashboard(historical_data_dir, output_dir, timestamp=None):
    """
    Generate an interactive trend dashboard using Plotly
    
    Args:
        historical_data_dir: Directory containing historical audit data
        output_dir: Directory to save the output visualization
        timestamp: Optional timestamp for the output file
    
    Returns:
        Path to the generated HTML file
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Load historical data (same as in the previous function)
    historical_files = list(Path(historical_data_dir).glob("audit_*.json"))
    if len(historical_files) < 1:
        print("Insufficient historical data for trend analysis")
        return None
    
    # Process historical data
    trend_data = []
    for file_path in sorted(historical_files):
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Extract timestamp
        if 'metadata' in data and 'timestamp' in data['metadata']:
            timestamp_str = data['metadata']['timestamp']
        else:
            # Try to extract from filename
            timestamp_str = file_path.stem.replace('audit_', '')
        
        try:
            timestamp_dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
        except ValueError:
            # If timestamp format is different, use file modification time
            timestamp_dt = datetime.fromtimestamp(file_path.stat().st_mtime)
        
        # Extract compliance data
        for company, frameworks in data.get('results', {}).items():
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    trend_data.append({
                        'date': timestamp_dt,
                        'company': company,
                        'framework': framework,
                        'compliance_percentage': metrics.get('compliance_percentage', 0),
                        'risk_level': metrics.get('risk_level', 'CRITICAL'),
                        'passed_rules': metrics.get('passed_rules', 0),
                        'total_rules': metrics.get('total_rules', 0),
                        'pass_rate': metrics.get('passed_rules', 0) / metrics.get('total_rules', 1) * 100
                    })
    
    if not trend_data:
        print("No trend data found in historical files")
        return None
    
    # Convert to DataFrame for easier manipulation
    df_trend = pd.DataFrame(trend_data)
    
    # Sort by date to ensure chronological order
    df_trend = df_trend.sort_values('date')
    
    # Create interactive dashboard
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=(
            "Compliance Trend Over Time",
            "Risk Level Distribution Over Time",
            "Framework Comparison",
            "Company Performance"
        ),
        specs=[
            [{"type": "scatter"}, {"type": "bar"}],
            [{"type": "bar"}, {"type": "heatmap"}]
        ],
        vertical_spacing=0.12,
        horizontal_spacing=0.08
    )
    
    # 1. Compliance Trend Over Time (Top Left)
    companies = df_trend['company'].unique()
    frameworks = df_trend['framework'].unique()
    
    for company in companies:
        for framework in frameworks:
            subset = df_trend[(df_trend['company'] == company) & (df_trend['framework'] == framework)]
            if not subset.empty:
                fig.add_trace(
                    go.Scatter(
                        x=subset['date'],
                        y=subset['compliance_percentage'],
                        mode='lines+markers',
                        name=f"{company} - {framework}",
                        hovertemplate=(
                            "<b>%{y:.1f}%</b> compliance<br>" +
                            "Date: %{x|%Y-%m-%d}<br>" +
                            f"Company: {company}<br>" +
                            f"Framework: {framework}<br>" +
                            "Risk: %{text}"
                        ),
                        text=subset['risk_level'],
                        line=dict(width=3)
                    ),
                    row=1, col=1
                )
    
    # Add risk level reference lines
    risk_levels = [
        ('CRITICAL', 25, '#8B0000'),
        ('HIGH', 50, '#FF4444'),
        ('MEDIUM', 75, '#FFA500'),
        ('LOW', 85, '#FFD700')
    ]
    
    for level, threshold, color in risk_levels:
        fig.add_shape(
            type="line",
            x0=df_trend['date'].min(),
            y0=threshold,
            x1=df_trend['date'].max(),
            y1=threshold,
            line=dict(color=color, width=1, dash="dash"),
            row=1, col=1
        )
        
        fig.add_annotation(
            x=df_trend['date'].min(),
            y=threshold,
            text=level,
            showarrow=False,
            font=dict(color=color),
            xanchor="left",
            yanchor="bottom",
            row=1, col=1
        )
    
    # 2. Risk Level Distribution Over Time (Top Right)
    risk_evolution = df_trend.groupby(['date', 'risk_level']).size().unstack(fill_value=0)
    
    for risk_level in risk_evolution.columns:
        if risk_level in RISK_COLORS:
            fig.add_trace(
                go.Bar(
                    x=risk_evolution.index,
                    y=risk_evolution[risk_level],
                    name=risk_level,
                    marker_color=RISK_COLORS[risk_level],
                    hovertemplate=(
                        "<b>%{y}</b> assessments<br>" +
                        "Date: %{x|%Y-%m-%d}<br>" +
                        f"Risk Level: {risk_level}"
                    )
                ),
                row=1, col=2
            )
    
    # 3. Framework Comparison (Bottom Left)
    framework_avg = df_trend.groupby(['framework', 'date'])['compliance_percentage'].mean().reset_index()
    
    for framework in frameworks:
        subset = framework_avg[framework_avg['framework'] == framework]
        if not subset.empty:
            fig.add_trace(
                go.Bar(
                    x=subset['date'],
                    y=subset['compliance_percentage'],
                    name=f"{framework} Avg",
                    hovertemplate=(
                        "<b>%{y:.1f}%</b> compliance<br>" +
                        "Date: %{x|%Y-%m-%d}<br>" +
                        f"Framework: {framework}"
                    )
                ),
                row=2, col=1
            )
    
    # 4. Company Performance Heatmap (Bottom Right)
    # Get the latest date
    latest_date = df_trend['date'].max()
    latest_data = df_trend[df_trend['date'] == latest_date]
    
    # Create pivot table for heatmap
    heatmap_data = latest_data.pivot_table(
        values='compliance_percentage',
        index='company',
        columns='framework',
        aggfunc='mean'
    )
    
    fig.add_trace(
        go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns,
            y=heatmap_data.index,
            colorscale=[
                [0, '#8B0000'],      # Dark red for 0%
                [0.25, '#FF4444'],   # Red for 25%
                [0.5, '#FFA500'],    # Orange for 50%
                [0.75, '#FFD700'],   # Yellow for 75%
                [0.85, '#90EE90'],   # Light green for 85%
                [1, '#4CAF50']       # Green for 100%
            ],
            colorbar=dict(
                title="Compliance %",
                titleside="right"
            ),
            hovertemplate=(
                "<b>%{z:.1f}%</b> compliance<br>" +
                "Company: %{y}<br>" +
                "Framework: %{x}<br>"
            ),
            text=[[f"{val:.1f}%" for val in row] for row in heatmap_data.values],
            texttemplate="%{text}",
            textfont={"size": 12}
        ),
        row=2, col=2
    )
    
    # Update layout
    fig.update_layout(
        title_text="Interactive Compliance Trend Dashboard",
        title_font_size=24,
        height=900,
        legend_title_text="Company - Framework",
        hovermode="closest",
        barmode="stack",
        template="plotly_white"
    )
    
    # Update axes
    fig.update_xaxes(title_text="Date", row=1, col=1)
    fig.update_yaxes(title_text="Compliance Percentage (%)", range=[0, 105], row=1, col=1)
    
    fig.update_xaxes(title_text="Date", row=1, col=2)
    fig.update_yaxes(title_text="Number of Assessments", row=1, col=2)
    
    fig.update_xaxes(title_text="Date", row=2, col=1)
    fig.update_yaxes(title_text="Average Compliance (%)", range=[0, 105], row=2, col=1)
    
    fig.update_xaxes(title_text="Framework", row=2, col=2)
    fig.update_yaxes(title_text="Company", row=2, col=2)
    
    # Save as HTML
    output_file = output_path / f"interactive_trend_dashboard_{timestamp}.html"
    fig.write_html(str(output_file), include_plotlyjs='cdn')
    
    print(f"Interactive trend dashboard saved to: {output_file}")
    return output_file

def generate_enhanced_heatmap(results, output_dir, timestamp=None):
    """
    Generate an enhanced compliance heatmap that is clearer and more informative
    
    Args:
        results: Dictionary containing compliance results
        output_dir: Directory to save the output visualization
        timestamp: Optional timestamp for the output file
    
    Returns:
        Path to the generated visualization file
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Extract frameworks and companies
    frameworks = []
    companies = []
    for company, data in results.items():
        companies.append(company)
        for framework in data.keys():
            if framework != 'overall' and framework not in frameworks:
                frameworks.append(framework)
    
    # Create heatmap data
    heatmap_data = np.zeros((len(frameworks), len(companies)))
    annotations = []
    
    for i, framework in enumerate(frameworks):
        for j, company in enumerate(companies):
            if framework in results[company]:
                compliance_pct = results[company][framework]['compliance_percentage']
                risk_level = results[company][framework]['risk_level']
                passed_rules = results[company][framework]['passed_rules']
                total_rules = results[company][framework]['total_rules']
                
                heatmap_data[i, j] = compliance_pct
                
                # Create detailed annotation
                annotations.append({
                    'text': f"{compliance_pct:.1f}%\n{risk_level}\n{passed_rules}/{total_rules}",
                    'x': j, 'y': i,
                    'color': 'white' if compliance_pct < 50 else 'black'
                })
    
    # Create enhanced heatmap
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # Custom colormap with clear risk level transitions
    colors_list = ['#8B0000', '#FF4444', '#FFA500', '#FFD700', '#4CAF50']
    cmap = plt.cm.colors.LinearSegmentedColormap.from_list('risk_cmap', colors_list, N=100)
    
    im = ax.imshow(heatmap_data, cmap=cmap, aspect='auto', vmin=0, vmax=100)
    
    # Add detailed annotations
    for ann in annotations:
        ax.text(ann['x'], ann['y'], ann['text'], 
               ha='center', va='center', color=ann['color'], 
               fontsize=10, fontweight='bold')
    
    # Customize axes
    ax.set_xticks(range(len(companies)))
    ax.set_yticks(range(len(frameworks)))
    ax.set_xticklabels([c.upper() for c in companies], rotation=45, ha='right', fontsize=12)
    ax.set_yticklabels(frameworks, fontsize=12)
    
    # Add colorbar with risk level indicators
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Compliance Percentage (%)', rotation=270, labelpad=20, fontsize=12)
    
    # Add risk level indicators to colorbar
    risk_levels = [
        ('CRITICAL', 25),
        ('HIGH', 50),
        ('MEDIUM', 75),
        ('LOW', 85),
        ('EXCELLENT', 95)
    ]
    
    for level, threshold in risk_levels:
        cbar.ax.axhline(y=threshold/100, color='black', linestyle='-', linewidth=1)
        cbar.ax.text(1.5, threshold/100, level, ha='left', va='center', fontsize=10)
    
    # Add title and labels
    plt.title('Enhanced Compliance Heatmap\nFramework vs Company Performance', 
             fontsize=18, fontweight='bold', pad=20)
    plt.xlabel('Companies', fontsize=14, fontweight='bold')
    plt.ylabel('Compliance Frameworks', fontsize=14, fontweight='bold')
    
    # Add a legend explaining the cell format
    legend_text = "Cell Format:\nCompliance %\nRisk Level\nPassed/Total Rules"
    props = dict(boxstyle='round', facecolor='white', alpha=0.8)
    ax.text(1.02, 0.5, legend_text, transform=ax.transAxes, fontsize=12,
           verticalalignment='center', bbox=props)
    
    plt.tight_layout()
    output_file = output_path / f"enhanced_heatmap_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print(f"Enhanced heatmap saved to: {output_file}")
    return output_file

def generate_executive_dashboard(results, output_dir, timestamp=None):
    """
    Generate a clear executive summary dashboard
    
    Args:
        results: Dictionary containing compliance results
        output_dir: Directory to save the output visualization
        timestamp: Optional timestamp for the output file
    
    Returns:
        Path to the generated visualization file
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Extract overall metrics
    companies = list(results.keys())
    overall_compliance = [results[company]['overall']['compliance_percentage'] for company in companies]
    risk_levels = [results[company]['overall']['risk_level'] for company in companies]
    
    # Count issues by severity
    critical_issues = [results[company]['overall'].get('total_critical_issues', 0) for company in companies]
    high_issues = [results[company]['overall'].get('total_high_issues', 0) for company in companies]
    
    # Create a 2x2 dashboard
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(20, 16))
    
    # 1. Overall Compliance Gauge Chart (Top Left)
    avg_compliance = np.mean(overall_compliance)
    
    # Create a half-circle gauge
    theta = np.linspace(0, np.pi, 100)
    r = 1.0
    
    # Plot the gauge background
    for threshold, color in [(0, '#8B0000'), (25, '#FF4444'), (50, '#FFA500'), (75, '#FFD700'), (85, '#4CAF50')]:
        end_angle = np.pi * min(threshold, 100) / 100
        mask = (theta <= end_angle)
        ax1.plot(r * np.cos(theta[mask]), r * np.sin(theta[mask]), color=color, linewidth=20, solid_capstyle='butt')
    
    # Plot the needle
    needle_angle = np.pi * min(avg_compliance, 100) / 100
    ax1.plot([0, r * np.cos(needle_angle)], [0, r * np.sin(needle_angle)], 'k-', linewidth=3)
    ax1.add_patch(plt.Circle((0, 0), 0.05, color='black'))
    
    # Add labels
    ax1.text(0, -0.2, f"{avg_compliance:.1f}%", ha='center', va='center', fontsize=36, fontweight='bold')
    ax1.text(0, -0.4, "Average Compliance", ha='center', va='center', fontsize=18)
    
    # Add risk level labels
    for threshold, label in [(12.5, 'CRITICAL'), (37.5, 'HIGH'), (62.5, 'MEDIUM'), (80, 'LOW'), (92.5, 'EXCELLENT')]:
        angle = np.pi * threshold / 100
        ax1.text(1.1 * r * np.cos(angle), 1.1 * r * np.sin(angle), label,
                ha='center', va='center', fontsize=12, fontweight='bold')
    
    # Set equal aspect ratio and remove axes
    ax1.set_aspect('equal')
    ax1.axis('off')
    
    # 2. Company Risk Distribution (Top Right)
    risk_colors = [RISK_COLORS.get(level, '#CCCCCC') for level in risk_levels]
    
    # Sort companies by compliance percentage
    sorted_indices = np.argsort(overall_compliance)
    sorted_companies = [companies[i] for i in sorted_indices]
    sorted_compliance = [overall_compliance[i] for i in sorted_indices]
    sorted_colors = [risk_colors[i] for i in sorted_indices]
    
    bars = ax2.barh(sorted_companies, sorted_compliance, color=sorted_colors)
    
    # Add value labels
    for i, bar in enumerate(bars):
        width = bar.get_width()
        label_color = 'white' if width < 50 else 'black'
        ax2.text(width - 5, bar.get_y() + bar.get_height()/2, f"{width:.1f}%",
                ha='right', va='center', color=label_color, fontweight='bold', fontsize=12)
    
    # Add risk level indicators
    for i, (company, compliance, color) in enumerate(zip(sorted_companies, sorted_compliance, sorted_colors)):
        risk_level = risk_levels[companies.index(company)]
        ax2.text(5, i, f"{risk_level}", ha='left', va='center',
                color='white', fontweight='bold', fontsize=10,
                bbox=dict(facecolor=color, alpha=0.8, boxstyle='round,pad=0.3'))
    
    ax2.set_title('Company Compliance Ranking', fontsize=16, fontweight='bold')
    ax2.set_xlabel('Compliance Percentage (%)', fontsize=12)
    ax2.grid(True, axis='x', alpha=0.3)
    
    # 3. Critical Issues by Company (Bottom Left)
    company_issues = []
    for i, company in enumerate(companies):
        company_issues.append({
            'company': company,
            'critical': critical_issues[i],
            'high': high_issues[i],
            'total': critical_issues[i] + high_issues[i]
        })
    
    # Sort by total issues
    company_issues.sort(key=lambda x: x['total'], reverse=True)
    
    # Create stacked bar chart
    companies_sorted = [item['company'] for item in company_issues]
    critical_sorted = [item['critical'] for item in company_issues]
    high_sorted = [item['high'] for item in company_issues]
    
    ax3.barh(companies_sorted, critical_sorted, color='#8B0000', label='Critical')
    ax3.barh(companies_sorted, high_sorted, left=critical_sorted, color='#FF4444', label='High')
    
    # Add value labels
    for i, company in enumerate(companies_sorted):
        total = company_issues[i]['total']
        if total > 0:
            ax3.text(total + 0.5, i, f"{total}", va='center', ha='left', fontweight='bold')
    
    ax3.set_title('Critical & High Issues by Company', fontsize=16, fontweight='bold')
    ax3.set_xlabel('Number of Issues', fontsize=12)
    ax3.legend(loc='upper right')
    ax3.grid(True, axis='x', alpha=0.3)
    
    # 4. Framework Compliance Comparison (Bottom Right)
    if 'CIS' in results[companies[0]] and 'ISO27001' in results[companies[0]] and 'RBI' in results[companies[0]]:
        framework_data = []
        for company in companies:
            for framework in ['CIS', 'ISO27001', 'RBI']:
                if framework in results[company] and framework != 'overall':
                    framework_data.append({
                        'company': company,
                        'framework': framework,
                        'compliance': results[company][framework]['compliance_percentage']
                    })
        
        if framework_data:
            df_framework = pd.DataFrame(framework_data)
            pivot_data = df_framework.pivot(index='company', columns='framework', values='compliance')
            
            # Create heatmap
            sns.heatmap(pivot_data, annot=True, fmt='.1f', cmap=risk_cmap,
                       ax=ax4, cbar_kws={'label': 'Compliance %'})
            
            ax4.set_title('Framework Compliance Comparison', fontsize=16, fontweight='bold')
    else:
        # If framework data is not available, show a summary pie chart of risk levels
        risk_counts = {}
        for level in risk_levels:
            risk_counts[level] = risk_counts.get(level, 0) + 1
        
        wedges, texts, autotexts = ax4.pie(
            list(risk_counts.values()),
            labels=list(risk_counts.keys()),
            autopct='%1.1f%%',
            colors=[RISK_COLORS.get(level, '#CCCCCC') for level in risk_counts.keys()],
            startangle=90
        )
        
        # Make text more readable
        for text in texts:
            text.set_fontsize(12)
        for autotext in autotexts:
            autotext.set_fontsize(12)
            autotext.set_fontweight('bold')
        
        ax4.set_title('Risk Level Distribution', fontsize=16, fontweight='bold')
    
    # Add overall title
    plt.suptitle('Executive Compliance Dashboard', fontsize=24, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # Save the figure
    output_file = output_path / f"executive_dashboard_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print(f"Executive dashboard saved to: {output_file}")
    return output_file

def generate_compliance_gap_analysis(results, output_dir, timestamp=None):
    """
    Generate a gap analysis visualization showing the difference between current and target compliance
    
    Args:
        results: Dictionary containing compliance results
        output_dir: Directory to save the output visualization
        timestamp: Optional timestamp for the output file
    
    Returns:
        Path to the generated visualization file
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Extract data for gap analysis
    gap_data = []
    
    for company, frameworks in results.items():
        for framework, metrics in frameworks.items():
            if framework != 'overall':
                # For each category, calculate the gap
                for category, stats in metrics.get('category_breakdown', {}).items():
                    current = stats.get('compliance_pct', 0)
                    target = 85  # Default target (LOW risk threshold)
                    gap = target - current
                    
                    if gap > 0:  # Only include categories with gaps
                        gap_data.append({
                            'company': company,
                            'framework': framework,
                            'category': category,
                            'current': current,
                            'target': target,
                            'gap': gap
                        })
    
    if not gap_data:
        print("No gap data found for analysis")
        return None
    
    # Convert to DataFrame
    df_gap = pd.DataFrame(gap_data)
    
    # Sort by gap size (descending)
    df_gap = df_gap.sort_values('gap', ascending=False)
    
    # Create figure
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 16), gridspec_kw={'height_ratios': [2, 1]})
    
    # 1. Top gaps by category across all companies
    top_gaps = df_gap.groupby('category')['gap'].mean().sort_values(ascending=False).head(10)
    
    # Create horizontal bar chart
    bars = ax1.barh(top_gaps.index, top_gaps.values, color='#FF4444')
    
    # Add value labels
    for i, (category, gap) in enumerate(top_gaps.items()):
        ax1.text(gap + 0.5, i, f"{gap:.1f}%", va='center', ha='left', fontweight='bold')
    
    # Add target line
    ax1.axvline(x=0, color='black', linestyle='-', alpha=0.5)
    
    # Customize the plot
    ax1.set_title('Top 10 Compliance Gaps by Category', fontsize=16, fontweight='bold')
    ax1.set_xlabel('Average Gap to Target (%)', fontsize=12, fontweight='bold')
    ax1.grid(True, axis='x', alpha=0.3)
    
    # 2. Company-specific gaps
    if len(df_gap['company'].unique()) > 1:
        # Get top 3 companies with largest gaps
        company_gaps = df_gap.groupby('company')['gap'].mean().sort_values(ascending=False).head(3)
        companies_to_show = company_gaps.index.tolist()
        
        # Filter data for these companies
        company_data = df_gap[df_gap['company'].isin(companies_to_show)]
        
        # For each company, show top 5 category gaps
        company_colors = ['#FF4444', '#FFA500', '#FFD700']
        
        for i, company in enumerate(companies_to_show):
            company_subset = company_data[company_data['company'] == company]
            top_company_gaps = company_subset.sort_values('gap', ascending=False).head(5)
            
            # Plot with slight offset for each company
            offset = i * 0.3
            ax2.barh(
                [f"{row['category']} ({company})" for _, row in top_company_gaps.iterrows()],
                top_company_gaps['gap'].values,
                color=company_colors[i],
                alpha=0.8,
                label=company
            )
        
        # Customize the plot
        ax2.set_title('Top 5 Gaps for Companies with Largest Compliance Issues', fontsize=16, fontweight='bold')
        ax2.set_xlabel('Gap to Target (%)', fontsize=12, fontweight='bold')
        ax2.grid(True, axis='x', alpha=0.3)
        ax2.legend(loc='upper right')
    else:
        # Single company - show all gaps
        company = df_gap['company'].iloc[0]
        top_company_gaps = df_gap.sort_values('gap', ascending=False).head(10)
        
        # Create horizontal bar chart with current and target
        categories = [row['category'] for _, row in top_company_gaps.iterrows()]
        current_values = top_company_gaps['current'].values
        target_values = top_company_gaps['target'].values
        
        # Plot current values
        ax2.barh(categories, current_values, color='#4CAF50', alpha=0.6, label='Current')
        
        # Plot target values (transparent)
        ax2.barh(categories, target_values, color='#FFD700', alpha=0.3, label='Target')
        
        # Add gap labels
        for i, (_, row) in enumerate(top_company_gaps.iterrows()):
            ax2.text(
                row['current'] + 1, i,
                f"Gap: {row['gap']:.1f}%",
                va='center', ha='left', fontweight='bold',
                bbox=dict(facecolor='white', alpha=0.7, boxstyle='round,pad=0.2')
            )
        
        # Customize the plot
        ax2.set_title(f'Compliance Gaps for {company}', fontsize=16, fontweight='bold')
        ax2.set_xlabel('Compliance Percentage (%)', fontsize=12, fontweight='bold')
        ax2.set_xlim(0, 100)
        ax2.grid(True, axis='x', alpha=0.3)
        ax2.legend(loc='upper right')
    
    # Add overall title
    plt.suptitle('Compliance Gap Analysis', fontsize=24, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # Save the figure
    output_file = output_path / f"compliance_gap_analysis_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print(f"Compliance gap analysis saved to: {output_file}")
    return output_file