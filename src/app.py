"""
Security Threat Analyzer - Professional UI
Enhanced with visualizations and polished design
"""

import streamlit as st
from services.threat_analyzer import ThreatAnalyzer
from services.nvd_client import NVDClient
from utils.visualizations import (
    create_cvss_gauge, 
    create_cvss_breakdown, 
    create_timeline_indicator
)

# Page configuration
st.set_page_config(
    page_title="Security Threat Analyzer",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3a8a 0%, #3b82f6 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .main-header h1 {
        color: white;
        margin: 0;
    }
    .main-header p {
        color: #e0e7ff;
        margin: 0.5rem 0 0 0;
    }
    .stButton>button {
        width: 100%;
    }
    .metric-card {
        background: #f8fafc;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #3b82f6;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>Security Threat Analyzer</h1>
    <p>AI-powered vulnerability analysis with real-time CVE intelligence</p>
</div>
""", unsafe_allow_html=True)

# Initialize services
@st.cache_resource
def get_analyzer():
    """Initialize and cache the ThreatAnalyzer instance."""
    try:
        return ThreatAnalyzer()
    except ValueError as e:
        st.error(f"⚠️ Configuration Error: {str(e)}")
        st.info("💡 Make sure your .env file contains a valid OPENAI_API_KEY")
        st.stop()

@st.cache_resource
def get_nvd_client():
    """Initialize and cache the NVD client."""
    return NVDClient()

analyzer = get_analyzer()
nvd_client = get_nvd_client()

# Test connection on first load
if 'connection_tested' not in st.session_state:
    with st.spinner("🔌 Testing API connection..."):
        if analyzer.test_connection():
            st.success("✅ OpenAI API connected successfully", icon="✅")
            st.session_state.connection_tested = True
        else:
            st.error("❌ API connection failed. Check your API key in .env file", icon="❌")
            st.stop()

# Input method selection
st.markdown("### 📥 Input Method")
input_method = st.radio(
    "Choose how to provide vulnerability data:",
    options=["🌐 Fetch CVE from NVD", "✍️ Paste Manual Report"],
    horizontal=True,
    label_visibility="collapsed"
)

# Main interface based on input method
if "Fetch CVE" in input_method:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 🔍 CVE Database Lookup")
        
        col_input, col_examples = st.columns([3, 1])
        
        with col_input:
            cve_input = st.text_input(
                "Enter CVE ID:",
                placeholder="CVE-2024-21762",
                help="Format: CVE-YYYY-NNNNN",
                label_visibility="collapsed"
            )
        
        with col_examples:
            st.markdown("**Examples:**")
            if st.button("CVE-2024-21762", help="Fortinet vulnerability"):
                st.session_state.cve_example = "CVE-2024-21762"
                st.rerun()
        
        # Use example if clicked
        if 'cve_example' in st.session_state:
            cve_input = st.session_state.cve_example
            del st.session_state.cve_example
        
        fetch_button = st.button("🌐 Fetch from NVD Database", type="secondary", use_container_width=True)
        
        if fetch_button and cve_input:
            with st.spinner(f"🔎 Searching NVD database for {cve_input}..."):
                cve_data = nvd_client.get_cve(cve_input)
            
            if cve_data:
                st.success(f"✅ Successfully retrieved {cve_input}", icon="✅")
                
                # Store in session state
                st.session_state.cve_data = cve_data
                st.session_state.report_text = nvd_client.format_for_analysis(cve_data)
                
                # Display CVE visualization
                st.markdown("---")
                st.markdown("### 📊 CVE Metrics Overview")
                
                viz_col1, viz_col2 = st.columns(2)
                
                with viz_col1:
                    # CVSS Gauge
                    gauge_fig = create_cvss_gauge(
                        cve_data.get('cvss_score'),
                        cve_data.get('cvss_severity', 'Unknown')
                    )
                    st.plotly_chart(gauge_fig, use_container_width=True)
                
                with viz_col2:
                    # CVSS Breakdown
                    breakdown_fig = create_cvss_breakdown(cve_data)
                    st.plotly_chart(breakdown_fig, use_container_width=True)
                
                # Timeline
                timeline_fig = create_timeline_indicator(
                    cve_data.get('published_date', ''),
                    cve_data.get('modified_date', '')
                )
                st.plotly_chart(timeline_fig, use_container_width=True)
                
                # Detailed CVE info in expander
                with st.expander("📄 View Full CVE Details", expanded=False):
                    st.markdown("**Description:**")
                    st.write(cve_data.get('description', 'No description available'))
                    
                    if cve_data.get('cwe_ids'):
                        st.markdown("**Weakness Types (CWE):**")
                        for cwe in cve_data['cwe_ids'][:3]:
                            st.code(cwe)
                    
                    if cve_data.get('references'):
                        st.markdown("**References:**")
                        for ref in cve_data['references'][:5]:
                            st.markdown(f"- [{ref}]({ref})")
            else:
                st.error("❌ CVE not found or error occurred", icon="❌")
                st.info("💡 Tips: Check CVE ID format (CVE-YYYY-NNNNN) or try a different CVE")
                st.session_state.cve_data = None
    
    with col2:
        st.markdown("### ⚙️ Analysis Configuration")
        
        target_audience = st.radio(
            "Target Audience:",
            options=["technical", "management", "executive"],
            help="Adjust analysis depth and terminology",
            format_func=lambda x: f"👨‍💻 {x.title()}" if x == "technical" else f"👔 {x.title()}" if x == "management" else f"💼 {x.title()}"
        )
        
        st.markdown("---")
        
        analyze_button = st.button(
            "🔍 Generate AI Analysis", 
            type="primary", 
            use_container_width=True,
            disabled='cve_data' not in st.session_state
        )
        
        if 'cve_data' not in st.session_state:
            st.info("ℹ️ Fetch a CVE first to enable analysis")

else:  # Manual report input
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### ✍️ Manual Vulnerability Report")
        
        # Sample CVE for testing
        sample_cve = """CVE-2024-1234: Critical Remote Code Execution in Apache WebServer

A heap-based buffer overflow vulnerability exists in Apache HTTP Server versions 2.4.0 through 2.4.58. 
An authenticated attacker can exploit this vulnerability by sending specially crafted HTTP requests 
to execute arbitrary code with the privileges of the web server process.

CVSS Score: 9.8 (Critical)
Attack Vector: Network
Attack Complexity: Low
Privileges Required: None
User Interaction: None

Affected versions: Apache HTTP Server 2.4.0 - 2.4.58
Fixed in: Version 2.4.59"""

        report_input = st.text_area(
            "Paste CVE or security bulletin:",
            value=sample_cve,
            height=300,
            help="Paste any vulnerability report, security advisory, or CVE description"
        )
        
        # Store in session state
        st.session_state.report_text = report_input
    
    with col2:
        st.markdown("### ⚙️ Analysis Configuration")
        
        target_audience = st.radio(
            "Target Audience:",
            options=["technical", "management", "executive"],
            help="Adjust analysis depth and terminology",
            format_func=lambda x: f"👨‍💻 {x.title()}" if x == "technical" else f"👔 {x.title()}" if x == "management" else f"💼 {x.title()}"
        )
        
        st.markdown("---")
        
        analyze_button = st.button(
            "🔍 Generate AI Analysis", 
            type="primary", 
            use_container_width=True
        )

# Analysis results section
if analyze_button:
    report_text = st.session_state.get('report_text', '')
    
    if not report_text or not report_text.strip():
        st.warning("⚠️ Please provide vulnerability data to analyze", icon="⚠️")
    else:
        with st.spinner("🤖 AI is analyzing the threat... This may take 5-10 seconds"):
            result = analyzer.analyze_vulnerability(report_text, target_audience)
        
        if result:
            st.success("✅ Analysis completed successfully!", icon="✅")
            
            # Display results
            st.markdown("---")
            st.markdown("## 📊 Threat Analysis Results")
            
            # Top metrics
            severity = result.get('severity', 'Unknown')
            severity_colors = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }
            severity_emoji = severity_colors.get(severity, '⚪')
            
            metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
            
            with metric_col1:
                st.metric("Severity Level", f"{severity_emoji} {severity}")
            with metric_col2:
                st.metric("CVSS Score", result.get('cvss_score', 'N/A'))
            with metric_col3:
                st.metric("Analysis Type", target_audience.title())
            with metric_col4:
                st.metric("Model Used", "GPT-4o-mini")
            
            st.markdown("---")
            
            # Tabbed results
            tab1, tab2, tab3, tab4 = st.tabs([
                "📝 Executive Summary", 
                "💥 Technical Impact", 
                "🛠️ Remediation", 
                "📄 Full Report"
            ])
            
            with tab1:
                st.markdown("### Summary")
                st.info(result.get('summary', 'No summary available'))
            
            with tab2:
                col_impact1, col_impact2 = st.columns(2)
                
                with col_impact1:
                    st.markdown("### Technical Impact")
                    st.write(result.get('impact', 'No impact information available'))
                
                with col_impact2:
                    st.markdown("### Affected Systems")
                    st.write(result.get('affected_systems', 'No system information available'))
            
            with tab3:
                st.markdown("### Recommended Mitigation Steps")
                mitigation = result.get('mitigation', 'No mitigation steps available')
                st.warning(mitigation, icon="🛠️")
            
            with tab4:
                st.markdown("### Complete AI Analysis")
                st.text_area(
                    "Full Response:",
                    value=result.get('raw_analysis', ''),
                    height=500,
                    disabled=True,
                    label_visibility="collapsed"
                )
                
                with st.expander("🔍 Analysis Metadata"):
                    st.json({
                        "timestamp": result.get('analysis_timestamp'),
                        "model": result.get('model_used'),
                        "audience": result.get('target_audience'),
                        "temperature": 0.3
                    })
        else:
            st.error("❌ Analysis failed. Please try again or check your API configuration.", icon="❌")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #64748b; font-size: 0.9em; padding: 1rem;'>
    <p><strong>Security Threat Analyzer</strong> • Built with OpenAI GPT-4 • NVD API • Streamlit</p>
    <p style='font-size: 0.8em; margin-top: 0.5rem;'>⚠️ For research and educational purposes. Always verify findings with official sources.</p>
</div>
""", unsafe_allow_html=True)