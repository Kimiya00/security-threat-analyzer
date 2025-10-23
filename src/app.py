"""
Security Threat Analyzer - Streamlit Application
Enhanced with CVE auto-fetch from NVD API
"""

import streamlit as st
from services.threat_analyzer import ThreatAnalyzer
from services.nvd_client import NVDClient

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

# Initialize services
@st.cache_resource
def get_analyzer():
    """Initialize and cache the ThreatAnalyzer instance."""
    try:
        analyzer = ThreatAnalyzer()
        return analyzer
    except ValueError as e:
        st.error(f"Configuration Error: {str(e)}")
        st.stop()

@st.cache_resource
def get_nvd_client():
    """Initialize and cache the NVD client."""
    return NVDClient()

analyzer = get_analyzer()
nvd_client = get_nvd_client()

# Test connection on first load
if 'connection_tested' not in st.session_state:
    with st.spinner("Testing API connection..."):
        if analyzer.test_connection():
            st.success("✅ API connection successful")
            st.session_state.connection_tested = True
        else:
            st.error("❌ API connection failed. Check your API key in .env file")
            st.stop()

# Input method selection
st.subheader("📥 Input Method")
input_method = st.radio(
    "Choose how to provide vulnerability data:",
    options=["Fetch CVE from NVD", "Paste Manual Report"],
    horizontal=True
)

# Main interface based on input method
if input_method == "Fetch CVE from NVD":
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🔍 CVE Lookup")
        
        cve_input = st.text_input(
            "Enter CVE ID:",
            placeholder="CVE-2024-1234",
            help="Format: CVE-YYYY-NNNNN (e.g., CVE-2024-12345)"
        )
        
        fetch_button = st.button("🌐 Fetch from NVD", type="secondary", use_container_width=True)
        
        if fetch_button and cve_input:
            with st.spinner(f"Fetching {cve_input} from NVD database..."):
                cve_data = nvd_client.get_cve(cve_input)
            
            if cve_data:
                st.success(f"✅ Found {cve_input} in NVD database!")
                
                # Store in session state for analysis
                st.session_state.cve_data = cve_data
                st.session_state.report_text = nvd_client.format_for_analysis(cve_data)
                
                # Display CVE info
                with st.expander("📄 View CVE Details", expanded=True):
                    info_col1, info_col2, info_col3 = st.columns(3)
                    
                    with info_col1:
                        st.metric("CVSS Score", cve_data.get('cvss_score', 'N/A'))
                    with info_col2:
                        st.metric("Severity", cve_data.get('cvss_severity', 'Unknown'))
                    with info_col3:
                        st.metric("Attack Vector", cve_data.get('attack_vector', 'Unknown'))
                    
                    st.markdown("**Description:**")
                    st.write(cve_data.get('description', 'No description available'))
                    
                    if cve_data.get('references'):
                        st.markdown("**References:**")
                        for ref in cve_data['references'][:3]:
                            st.markdown(f"- {ref}")
            else:
                st.error("❌ CVE not found or error fetching data. Check the CVE ID format.")
                st.session_state.cve_data = None
    
    with col2:
        st.subheader("⚙️ Analysis Settings")
        
        target_audience = st.radio(
            "Target Audience:",
            options=["technical", "management", "executive"],
            help="Adjust the analysis depth and terminology for your audience"
        )
        
        analyze_button = st.button(
            "🔍 Analyze Threat", 
            type="primary", 
            use_container_width=True,
            disabled='cve_data' not in st.session_state
        )

else:  # Manual report input
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
            height=250,
            help="Enter the vulnerability report text you want to analyze"
        )
        
        # Store in session state
        st.session_state.report_text = report_input
    
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
    report_text = st.session_state.get('report_text', '')
    
    if not report_text or not report_text.strip():
        st.warning("Please provide vulnerability data to analyze")
    else:
        with st.spinner("Analyzing threat..."):
            result = analyzer.analyze_vulnerability(report_text, target_audience)
        
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
    Built with OpenAI GPT-4 • NVD API • Streamlit • Python
</div>
""", unsafe_allow_html=True)