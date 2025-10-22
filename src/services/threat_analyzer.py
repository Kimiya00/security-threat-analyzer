"""
Security threat analysis service using OpenAI GPT models.

This module handles all interactions with the LLM API, including
prompt construction, response parsing, and error handling.
"""

import os
from typing import Optional, Dict, Any
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class ThreatAnalyzer:
    """
    Analyzes security threats using LLM-powered natural language processing.
    
    Attributes:
        client: OpenAI API client instance
        model: Model identifier (default: gpt-4o-mini for cost efficiency)
    """
    
    def __init__(self, model: str = "gpt-4o-mini"):
        """
        Initialize the threat analyzer.
        
        Args:
            model: OpenAI model to use (gpt-4o-mini recommended for balance of cost/performance)
            
        Raises:
            ValueError: If OPENAI_API_KEY environment variable is not set
        """
        api_key = os.getenv("OPENAI_API_KEY")
        
        if not api_key:
            raise ValueError(
                "OpenAI API key not found. Please set OPENAI_API_KEY in .env file"
            )
        
        self.client = OpenAI(api_key=api_key)
        self.model = model
        
    def analyze_vulnerability(
        self, 
        report_text: str, 
        target_audience: str = "technical"
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a security vulnerability report and generate structured insights.
        
        Args:
            report_text: Raw vulnerability description (CVE, security bulletin, etc.)
            target_audience: One of 'technical', 'management', or 'executive'
            
        Returns:
            Dictionary containing:
                - severity: Risk level (Critical/High/Medium/Low)
                - cvss_score: Estimated CVSS score if available
                - impact: Technical impact description
                - affected_systems: Types of systems at risk
                - mitigation: Recommended remediation steps
                - summary: Audience-appropriate executive summary
                - analysis_timestamp: When analysis was performed
            
            Returns None if API call fails
        """
        if not report_text.strip():
            return None
            
        prompt = self._construct_prompt(report_text, target_audience)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system", 
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=0.3,  # Low temperature for consistent, factual output
                max_tokens=1000,
                timeout=30.0
            )
            
            content = response.choices[0].message.content
            parsed_result = self._parse_analysis(content, target_audience)
            
            # Add metadata
            parsed_result["analysis_timestamp"] = datetime.now().isoformat()
            parsed_result["model_used"] = self.model
            
            return parsed_result
            
        except Exception as e:
            # In production, you'd use proper logging here
            print(f"Error during threat analysis: {type(e).__name__} - {str(e)}")
            return None
    
    def _get_system_prompt(self) -> str:
        """
        Returns the system prompt that defines the AI's role.
        
        This is separate from the user prompt and sets the behavioral context.
        """
        return """You are a senior cybersecurity analyst with expertise in vulnerability assessment, 
threat intelligence, and risk communication. Your role is to analyze security reports and provide 
clear, actionable insights. Be precise with technical details but explain implications clearly."""
    
    def _construct_prompt(self, report_text: str, audience: str) -> str:
        """
        Build the analysis prompt with audience-specific instructions.
        
        Args:
            report_text: The vulnerability report to analyze
            audience: Target audience level
            
        Returns:
            Formatted prompt string
        """
        audience_guidance = {
            "technical": "Focus on technical implementation details and IOCs. Assume audience understands CVSS, exploit chains, and security controls.",
            "management": "Balance technical accuracy with business impact. Include resource requirements and timeline recommendations.",
            "executive": "Prioritize business risk and compliance implications. Minimize jargon and focus on decision-making factors."
        }
        
        guidance = audience_guidance.get(audience, audience_guidance["technical"])
        
        prompt = f"""Analyze the following security vulnerability report:

{report_text}

Provide a structured analysis with these components:

1. SEVERITY: Assign a risk level (Critical/High/Medium/Low) based on exploitability, impact, and attack complexity

2. CVSS SCORE: If information is available, provide or estimate a CVSS v3 score

3. TECHNICAL IMPACT: What can an attacker achieve by exploiting this vulnerability?

4. AFFECTED SYSTEMS: What types of systems, software, or configurations are vulnerable?

5. MITIGATION STEPS: Specific, actionable remediation steps in priority order

6. SUMMARY: A concise summary appropriate for a {audience} audience

Audience context: {guidance}

Format your response with clear section headers."""
        
        return prompt
    
    def _parse_analysis(self, content: str, audience: str) -> Dict[str, Any]:
        """
        Parse the LLM response into a structured dictionary.
        
        This uses simple string parsing. In a production system, you might
        use more sophisticated parsing or structured output from the LLM.
        
        Args:
            content: Raw LLM response text
            audience: Target audience (for context)
            
        Returns:
            Dictionary with extracted fields
        """
        result = {
            "severity": self._extract_field(content, "SEVERITY"),
            "cvss_score": self._extract_field(content, "CVSS SCORE"),
            "impact": self._extract_field(content, "TECHNICAL IMPACT"),
            "affected_systems": self._extract_field(content, "AFFECTED SYSTEMS"),
            "mitigation": self._extract_field(content, "MITIGATION"),
            "summary": self._extract_field(content, "SUMMARY"),
            "target_audience": audience,
            "raw_analysis": content
        }
        
        return result
    
    def _extract_field(self, text: str, field_name: str) -> str:
        """
        Extract content for a specific field from the LLM response.
        
        Args:
            text: Full response text
            field_name: Section header to look for
            
        Returns:
            Extracted content or 'Not specified' if not found
        """
        lines = text.split('\n')
        capture = False
        result_lines = []
        
        for line in lines:
            # Check if this line is the field header
            if field_name in line.upper():
                capture = True
                continue
            
            # Stop capturing when we hit the next section header
            if capture and line.strip() and line.strip()[0].isdigit() and '.' in line[:3]:
                break
                
            if capture and line.strip():
                result_lines.append(line.strip())
        
        return ' '.join(result_lines) if result_lines else "Not specified"
    
    def test_connection(self) -> bool:
        """
        Test if the OpenAI API connection is working.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5
            )
            return True
        except Exception as e:
            print(f"Connection test failed: {str(e)}")
            return False