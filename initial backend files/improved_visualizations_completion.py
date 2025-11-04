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