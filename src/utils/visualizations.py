"""
Visualization utilities for security metrics and CVSS data.

Creates interactive charts using Plotly for threat analysis visualization.
"""

import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, Optional


def create_cvss_gauge(cvss_score: Optional[float], severity: str = "Unknown") -> go.Figure:
    """
    Create a gauge chart for CVSS score visualization.
    
    Args:
        cvss_score: CVSS base score (0-10)
        severity: Severity rating (Critical/High/Medium/Low)
        
    Returns:
        Plotly figure object
    """
    if cvss_score is None:
        cvss_score = 0
    
    # Color mapping based on CVSS severity
    severity_colors = {
        'Critical': '#d32f2f',  # Red
        'High': '#f57c00',      # Orange
        'Medium': '#fbc02d',    # Yellow
        'Low': '#388e3c',       # Green
        'Unknown': '#757575'    # Gray
    }
    
    color = severity_colors.get(severity, severity_colors['Unknown'])
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=cvss_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"CVSS Score<br><span style='font-size:0.8em;color:{color}'>{severity}</span>"},
        delta={'reference': 5.0, 'increasing': {'color': "red"}},
        gauge={
            'axis': {'range': [None, 10], 'tickwidth': 1, 'tickcolor': "darkgray"},
            'bar': {'color': color},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 4], 'color': '#c8e6c9'},    # Low
                {'range': [4, 7], 'color': '#fff9c4'},    # Medium
                {'range': [7, 9], 'color': '#ffccbc'},    # High
                {'range': [9, 10], 'color': '#ffcdd2'}    # Critical
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': cvss_score
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font={'size': 14}
    )
    
    return fig


def create_cvss_breakdown(cve_data: Dict) -> go.Figure:
    """
    Create a bar chart showing CVSS metric breakdown.
    
    Args:
        cve_data: CVE data dictionary from NVD client
        
    Returns:
        Plotly figure object
    """
    # Extract CVSS metrics
    metrics = {
        'Attack Vector': cve_data.get('attack_vector', 'Unknown'),
        'Attack Complexity': cve_data.get('attack_complexity', 'Unknown'),
        'Privileges Required': cve_data.get('privileges_required', 'Unknown'),
        'User Interaction': cve_data.get('user_interaction', 'Unknown')
    }
    
    # Convert to numeric scores for visualization
    metric_scores = {
        'Attack Vector': {
            'NETWORK': 3, 'ADJACENT_NETWORK': 2, 'LOCAL': 1, 'PHYSICAL': 0.5, 'Unknown': 0
        },
        'Attack Complexity': {
            'LOW': 3, 'HIGH': 1, 'Unknown': 0
        },
        'Privileges Required': {
            'NONE': 3, 'LOW': 2, 'HIGH': 1, 'Unknown': 0
        },
        'User Interaction': {
            'NONE': 3, 'REQUIRED': 1, 'Unknown': 0
        }
    }
    
    categories = []
    values = []
    colors_list = []
    
    for metric_name, metric_value in metrics.items():
        categories.append(metric_name)
        score = metric_scores[metric_name].get(metric_value, 0)
        values.append(score)
        
        # Color coding: higher values = more dangerous
        if score >= 3:
            colors_list.append('#d32f2f')  # Red
        elif score >= 2:
            colors_list.append('#f57c00')  # Orange
        elif score >= 1:
            colors_list.append('#fbc02d')  # Yellow
        else:
            colors_list.append('#388e3c')  # Green
    
    fig = go.Figure(data=[
        go.Bar(
            x=categories,
            y=values,
            text=[metrics[cat] for cat in categories],
            textposition='auto',
            marker_color=colors_list,
            hovertemplate='<b>%{x}</b><br>Level: %{text}<br>Risk Score: %{y}/3<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title="CVSS Metric Breakdown",
        xaxis_title="Metric",
        yaxis_title="Risk Level",
        yaxis=dict(range=[0, 3.5]),
        height=350,
        margin=dict(l=50, r=20, t=50, b=80),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(240,240,240,0.5)",
        font={'size': 12},
        showlegend=False
    )
    
    return fig


def create_severity_distribution(severity_counts: Dict[str, int]) -> go.Figure:
    """
    Create a pie chart showing severity distribution (for future multi-CVE analysis).
    
    Args:
        severity_counts: Dictionary mapping severity levels to counts
        
    Returns:
        Plotly figure object
    """
    severities = list(severity_counts.keys())
    counts = list(severity_counts.values())
    
    colors = {
        'Critical': '#d32f2f',
        'High': '#f57c00',
        'Medium': '#fbc02d',
        'Low': '#388e3c'
    }
    
    color_list = [colors.get(sev, '#757575') for sev in severities]
    
    fig = go.Figure(data=[
        go.Pie(
            labels=severities,
            values=counts,
            marker_colors=color_list,
            hole=0.3,
            textinfo='label+percent',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title="Severity Distribution",
        height=350,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font={'size': 12}
    )
    
    return fig


def create_timeline_indicator(published_date: str, modified_date: str) -> go.Figure:
    """
    Create a visual timeline showing CVE publication and modification dates.
    
    Args:
        published_date: ISO format publication date
        modified_date: ISO format last modified date
        
    Returns:
        Plotly figure object
    """
    from datetime import datetime
    
    try:
        pub_dt = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
        mod_dt = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
        
        dates = [pub_dt, mod_dt]
        labels = ['Published', 'Last Modified']
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=dates,
            y=[1, 1],
            mode='markers+text',
            marker=dict(size=20, color=['#1976d2', '#388e3c']),
            text=labels,
            textposition='top center',
            textfont=dict(size=12),
            hovertemplate='<b>%{text}</b><br>%{x|%Y-%m-%d %H:%M}<extra></extra>'
        ))
        
        # Add line connecting the points
        fig.add_trace(go.Scatter(
            x=dates,
            y=[1, 1],
            mode='lines',
            line=dict(color='gray', width=2, dash='dash'),
            showlegend=False,
            hoverinfo='skip'
        ))
        
        fig.update_layout(
            title="CVE Timeline",
            xaxis_title="Date",
            yaxis=dict(visible=False, range=[0.5, 1.5]),
            height=200,
            margin=dict(l=20, r=20, t=50, b=50),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={'size': 12}
        )
        
        return fig
        
    except Exception as e:
        # Return empty figure if date parsing fails
        fig = go.Figure()
        fig.add_annotation(
            text="Timeline unavailable",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=14, color="gray")
        )
        fig.update_layout(
            height=200,
            margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor="rgba(0,0,0,0)"
        )
        return fig