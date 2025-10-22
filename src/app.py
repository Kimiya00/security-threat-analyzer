"""
Security Threat Analyzer - Streamlit Application
Day 1 version for testing core functionality
"""

import streamlit as st
from services.threat_analyzer import ThreatAnalyzer

# Page configuration
st.set_page_config(
    page_title="Security Threat Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Title and description
st.title("🛡️ Security Threat Analyzer")
st.markdown("""
Analyze security vulnerabilities and generate audience-specific threat assessments 
using AI-powered natural language processing.
""")

# Initialize the analyzer
@st.cache_resource
def get_analyzer():
    """Initialize and cache the ThreatAnalyzer instance."""
    try:
        analyzer = ThreatAnalyzer()
        return analyzer
    except ValueError as e:
        st.error(f"Configuration Error: {str(e)}")
        st.stop()

analyzer = get_analyzer()

# Test connection on first load
if 'connection_tested' not in st.session_state:
    with st.spinner("Testing API connection..."):
        if analyzer.test_connection():
            st.success("✅ API connection successful")
            st.session_state.connection_tested = True
        else:
            st.error("❌ API connection failed. Check your API key in .env file")
            st.stop()

# Main interface
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Vulnerability Report Input")
    
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
        "Paste CVE or security report:",
        value=sample_cve,
        height=200,
        help="Enter the vulnerability report text you want to analyze"
    )

with col2:
    st.subheader("Analysis Settings")
    
    target_audience = st.radio(
        "Target Audience:",
        options=["technical", "management", "executive"],
        help="Adjust the analysis depth and terminology for your audience"
    )
    
    analyze_button = st.button("🔍 Analyze Threat", type="primary", use_container_width=True)

# Analysis results section
if analyze_button:
    if not report_input.strip():
        st.warning("Please enter a vulnerability report to analyze")
    else:
        with st.spinner("Analyzing threat..."):
            result = analyzer.analyze_vulnerability(report_input, target_audience)
        
        if result:
            st.success("Analysis complete!")
            
            # Display results in organized sections
            st.markdown("---")
            st.subheader("📊 Analysis Results")
            
            # Severity badge
            severity = result.get('severity', 'Unknown')
            severity_colors = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }
            severity_emoji = severity_colors.get(severity, '⚪')
            
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("Severity", f"{severity_emoji} {severity}")
            with col_b:
                st.metric("CVSS Score", result.get('cvss_score', 'N/A'))
            with col_c:
                st.metric("Audience", target_audience.title())
            
            # Tabbed interface for detailed results
            tab1, tab2, tab3, tab4 = st.tabs(["📝 Summary", "💥 Impact", "🛠️ Mitigation", "📄 Full Analysis"])
            
            with tab1:
                st.markdown("### Executive Summary")
                st.write(result.get('summary', 'No summary available'))
            
            with tab2:
                st.markdown("### Technical Impact")
                st.write(result.get('impact', 'No impact information available'))
                
                st.markdown("### Affected Systems")
                st.write(result.get('affected_systems', 'No system information available'))
            
            with tab3:
                st.markdown("### Recommended Mitigation Steps")
                st.write(result.get('mitigation', 'No mitigation steps available'))
            
            with tab4:
                st.markdown("### Complete Analysis")
                st.text_area(
                    "Full LLM Response:",
                    value=result.get('raw_analysis', ''),
                    height=400,
                    disabled=True
                )
                
                with st.expander("Analysis Metadata"):
                    st.json({
                        "timestamp": result.get('analysis_timestamp'),
                        "model": result.get('model_used'),
                        "audience": result.get('target_audience')
                    })
        else:
            st.error("Analysis failed. Please check the error message above and try again.")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; font-size: 0.9em;'>
    Built with OpenAI GPT-4 • Streamlit • Python
</div>
""", unsafe_allow_html=True)