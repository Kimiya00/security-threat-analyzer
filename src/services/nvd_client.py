"""
NVD (National Vulnerability Database) API client.

Fetches CVE data from the official NIST NVD REST API.
Documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
from typing import Optional, Dict, Any
from datetime import datetime


class NVDClient:
    """
    Client for interacting with the National Vulnerability Database API.
    
    The NVD API is free but rate-limited:
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds
    
    For this project, we'll use the free tier (no API key needed).
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
        """
        self.api_key = api_key
        self.session = requests.Session()
        
        # Set headers for better rate limit handling
        self.session.headers.update({
            'User-Agent': 'Security-Threat-Analyzer/1.0',
            'Accept': 'application/json'
        })
        
        if api_key:
            self.session.headers['apiKey'] = api_key
    
    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE details from NVD by CVE ID.
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            
        Returns:
            Dictionary with CVE details or None if not found/error
        """
        # Clean up CVE ID format
        cve_id = cve_id.strip().upper()
        
        if not self._validate_cve_format(cve_id):
            print(f"Invalid CVE ID format: {cve_id}")
            return None
        
        try:
            # Query NVD API
            response = self.session.get(
                self.BASE_URL,
                params={'cveId': cve_id},
                timeout=10
            )
            
            # Check rate limiting
            if response.status_code == 403:
                print("Rate limit exceeded. Please wait 30 seconds and try again.")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            # Parse response
            if data.get('totalResults', 0) == 0:
                print(f"CVE {cve_id} not found in NVD database")
                return None
            
            # Extract the first (and only) vulnerability
            vuln = data['vulnerabilities'][0]['cve']
            
            return self._parse_cve_data(vuln, cve_id)
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE data: {str(e)}")
            return None
    
    def _validate_cve_format(self, cve_id: str) -> bool:
        """
        Validate CVE ID format.
        
        Valid format: CVE-YYYY-NNNNN (where YYYY is year, NNNNN is 4+ digits)
        
        Args:
            cve_id: CVE identifier to validate
            
        Returns:
            True if valid format, False otherwise
        """
        import re
        pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(pattern, cve_id))
    
    def _parse_cve_data(self, vuln_data: Dict, cve_id: str) -> Dict[str, Any]:
        """
        Parse raw NVD API response into simplified format.
        
        Args:
            vuln_data: Raw vulnerability data from NVD
            cve_id: CVE identifier
            
        Returns:
            Simplified dictionary with key CVE information
        """
        # Extract description (English version)
        descriptions = vuln_data.get('descriptions', [])
        description = next(
            (d['value'] for d in descriptions if d.get('lang') == 'en'),
            "No description available"
        )
        
        # Extract CVSS scores (prefer v3.1, fallback to v3.0, then v2.0)
        cvss_data = self._extract_cvss_scores(vuln_data)
        
        # Extract references
        references = vuln_data.get('references', [])
        reference_urls = [ref.get('url') for ref in references[:5]]  # Limit to 5
        
        # Extract published and modified dates
        published = vuln_data.get('published', 'Unknown')
        modified = vuln_data.get('lastModified', 'Unknown')
        
        # Extract CWE (Common Weakness Enumeration)
        weaknesses = vuln_data.get('weaknesses', [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_ids.append(desc.get('value', ''))
        
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_data.get('score'),
            'cvss_severity': cvss_data.get('severity'),
            'cvss_vector': cvss_data.get('vector'),
            'attack_vector': cvss_data.get('attack_vector'),
            'attack_complexity': cvss_data.get('attack_complexity'),
            'privileges_required': cvss_data.get('privileges_required'),
            'user_interaction': cvss_data.get('user_interaction'),
            'published_date': published,
            'modified_date': modified,
            'cwe_ids': cwe_ids,
            'references': reference_urls,
            'raw_data': vuln_data  # Keep for advanced users
        }
    
    def _extract_cvss_scores(self, vuln_data: Dict) -> Dict[str, Any]:
        """
        Extract CVSS metrics from vulnerability data.
        
        Prefers CVSS v3.1, falls back to v3.0, then v2.0.
        
        Args:
            vuln_data: Raw vulnerability data
            
        Returns:
            Dictionary with CVSS score and metrics
        """
        metrics = vuln_data.get('metrics', {})
        
        # Try CVSS v3.1 first (most recent)
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss = metrics['cvssMetricV31'][0]['cvssData']
            return {
                'score': cvss.get('baseScore'),
                'severity': cvss.get('baseSeverity'),
                'vector': cvss.get('vectorString'),
                'attack_vector': cvss.get('attackVector'),
                'attack_complexity': cvss.get('attackComplexity'),
                'privileges_required': cvss.get('privilegesRequired'),
                'user_interaction': cvss.get('userInteraction'),
                'version': 'v3.1'
            }
        
        # Fall back to CVSS v3.0
        if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss = metrics['cvssMetricV30'][0]['cvssData']
            return {
                'score': cvss.get('baseScore'),
                'severity': cvss.get('baseSeverity'),
                'vector': cvss.get('vectorString'),
                'attack_vector': cvss.get('attackVector'),
                'attack_complexity': cvss.get('attackComplexity'),
                'privileges_required': cvss.get('privilegesRequired'),
                'user_interaction': cvss.get('userInteraction'),
                'version': 'v3.0'
            }
        
        # Fall back to CVSS v2.0 (legacy)
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss = metrics['cvssMetricV2'][0]['cvssData']
            return {
                'score': cvss.get('baseScore'),
                'severity': cvss.get('baseSeverity', 'Unknown'),
                'vector': cvss.get('vectorString'),
                'attack_vector': cvss.get('accessVector'),
                'attack_complexity': cvss.get('accessComplexity'),
                'privileges_required': 'N/A',
                'user_interaction': 'N/A',
                'version': 'v2.0'
            }
        
        return {
            'score': None,
            'severity': 'Unknown',
            'vector': None,
            'attack_vector': 'Unknown',
            'attack_complexity': 'Unknown',
            'privileges_required': 'Unknown',
            'user_interaction': 'Unknown',
            'version': None
        }
    
    def format_for_analysis(self, cve_data: Dict[str, Any]) -> str:
        """
        Format CVE data into a text report suitable for LLM analysis.
        
        Args:
            cve_data: Parsed CVE data from get_cve()
            
        Returns:
            Formatted text report
        """
        report = f"""CVE ID: {cve_data['cve_id']}

DESCRIPTION:
{cve_data['description']}

CVSS METRICS:
- Score: {cve_data['cvss_score']} ({cve_data['cvss_severity']})
- Vector String: {cve_data['cvss_vector']}
- Attack Vector: {cve_data['attack_vector']}
- Attack Complexity: {cve_data['attack_complexity']}
- Privileges Required: {cve_data['privileges_required']}
- User Interaction: {cve_data['user_interaction']}

TIMELINE:
- Published: {cve_data['published_date']}
- Last Modified: {cve_data['modified_date']}
"""
        
        if cve_data['cwe_ids']:
            report += f"\nWEAKNESS TYPES (CWE):\n"
            for cwe in cve_data['cwe_ids']:
                report += f"- {cwe}\n"
        
        if cve_data['references']:
            report += f"\nREFERENCES:\n"
            for url in cve_data['references']:
                report += f"- {url}\n"
        
        return report