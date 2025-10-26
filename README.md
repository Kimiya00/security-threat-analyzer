---
title: Security Threat Analyzer
colorFrom: blue
colorTo: indigo
sdk: streamlit
sdk_version: "1.31.0"
app_file: src/app.py
pinned: false
---

# Security Threat Analyzer

An LLM-powered application that automates vulnerability analysis by integrating OpenAI's GPT-4 with the National Vulnerability Database (NVD). Generates role-specific security assessments from CVE data in under 10 seconds.

**Live Demo:** (https://huggingface.co/spaces/Kimiya00/security-threat-analyzer)

## Demo

![Main Interface](screenshots/demo.png)
*CVE lookup interface with real-time NVD integration*

![Interactive Visualizations](screenshots/visualization.png)
*CVSS metrics dashboard with gauge, breakdown chart, and timeline*

![AI Analysis Results](screenshots/analysis.png)
*GPT-4 generated threat assessment with role-specific summaries*

---

## Problem

Security teams receive dozens of CVE alerts daily but lack time to properly assess each one. Reading technical bulletins, determining business impact, and communicating findings to non-technical stakeholders is time-consuming and inconsistent across teams.

## Solution

This tool automates the analysis pipeline:
- Fetches structured CVE data from NIST's official API
- Processes vulnerability details through GPT-4 with custom prompts
- Outputs tailored summaries for technical teams, management, or executives
- Visualizes CVSS metrics for quick risk assessment

Built in 2 weeks as a portfolio project to demonstrate applied AI systems for security operations.

## Features

**CVE Intelligence**
- Real-time data retrieval from NVD REST API v2.0
- Automatic parsing of CVSS v3.x metrics
- CWE mapping and reference extraction

**AI Analysis**
- GPT-4o-mini integration with role-specific prompt engineering
- Temperature tuning (0.3) for consistent security assessments
- Structured output parsing (severity, impact, mitigation steps)

**Visualization**
- CVSS score gauge (Plotly)
- Attack vector breakdown charts
- CVE timeline display

**User Interface**
- Streamlit web app with responsive layout
- Dual input modes: CVE lookup or manual paste
- Tabbed results view for different stakeholder needs

## Quick Start

**Requirements:** Python 3.10+, OpenAI API key

```bash
git clone https://github.com/Kimiya00/security-threat-analyzer.git
cd security-threat-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "OPENAI_API_KEY=your-key-here" > .env
streamlit run src/app.py
```

Visit `https://huggingface.co/spaces/Kimiya00/security-threat-analyzer` and try analyzing CVE-2024-21762.

## Technical Architecture

```
Web UI (Streamlit)
    ↓
Business Logic
    ↓
┌────────────┬────────────┐
│   OpenAI   │  NVD API   │
│   Client   │  Client    │
└────────────┴────────────┘
```

**Key Design Decisions:**

- **Separation of concerns:** API clients isolated in `services/`, visualization logic in `utils/`
- **Caching:** Streamlit's `@st.cache_resource` prevents redundant API initialization
- **Error handling:** Graceful degradation when APIs are unreachable
- **Rate limiting awareness:** NVD allows 5 requests/30sec without key; handled via user feedback

## Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| LLM | OpenAI GPT-4o-mini | 90% accuracy of GPT-4 at 5% cost ($0.15/1M tokens) |
| Data Source | NIST NVD API | Authoritative CVE database, free tier sufficient |
| Frontend | Streamlit | Rapid prototyping without React overhead |
| Visualization | Plotly | Interactive charts, better than Matplotlib for web |
| Deployment | Hugging Face Spaces | Free hosting, AI community visibility |

## Project Structure

```
src/
├── app.py                    # Streamlit interface
├── services/
│   ├── threat_analyzer.py    # GPT-4 API wrapper
│   └── nvd_client.py         # NVD data fetching
└── utils/
    └── visualizations.py     # Plotly chart generators

data/sample_cve.json          # Test fixture
screenshots/                  # Demo images
requirements.txt              # pip dependencies
.env                          # API keys (not committed)
```

**Why this structure:**
- Follows Python package conventions
- Easy to unit test individual services
- Clear separation between data, logic, and presentation

## Configuration

Create `.env` file in project root:
```
OPENAI_API_KEY=sk-proj-xxxxx
```

Optional: Add NVD API key for higher rate limits (50 req/30s instead of 5):
```
NVD_API_KEY=xxxxxx
```
*Get free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key*

Modify analysis behavior in `src/services/threat_analyzer.py`:
```python
temperature=0.3,      # Lower = more deterministic
max_tokens=1000,      # Response length limit
model="gpt-4o-mini"   # Switch to "gpt-4" for better quality
```

## Usage Examples

**Scenario 1: Quick CVE Assessment**
1. Select "Fetch CVE from NVD"
2. Enter CVE-2024-21762
3. Review CVSS gauge (9.6 Critical)
4. Choose "Executive" audience
5. Get 2-paragraph business impact summary

**Scenario 2: Custom Bulletin Analysis**
1. Select "Paste Manual Report"
2. Copy vendor security advisory
3. Choose "Technical" audience
4. Receive detailed exploit analysis and IOCs

## Cost Analysis

**Development:** ~$3 for 100+ test queries (GPT-4o-mini)  
**Production estimate:** $0.02-0.05 per analysis

NVD API is completely free.

## Testing

Try these real CVEs:
- `CVE-2024-21762` - Fortinet (Critical, 9.6)
- `CVE-2021-44228` - Log4Shell (Critical, 10.0)
- `CVE-2023-44487` - HTTP/2 Rapid Reset (High, 7.5)

Manual testing checklist:
- [ ] Valid CVE fetches successfully
- [ ] Invalid CVE shows clear error
- [ ] All audience types produce distinct outputs
- [ ] Charts render without errors
- [ ] Manual input mode works

## Known Limitations

- **No batch processing:** Analyzes one CVE at a time
- **Rate limits:** NVD free tier throttles at 5 req/30s
- **No persistence:** Results aren't saved (could add PostgreSQL)
- **English only:** Prompts optimized for English CVE descriptions

## Roadmap

**Phase 2 (Next):**
- Vector database integration for historical context (ChromaDB)
- PDF export functionality
- Batch CVE upload (CSV)

**Phase 3 (Future):**
- REST API wrapper for programmatic access
- Threat intel enrichment (AlienVault OTX)
- User authentication and analysis history

## What I Learned

**Prompt Engineering:**
- Temperature tuning matters: 0.3 vs 0.7 changed consistency significantly
- System prompts establish persona; user prompts provide structure
- Explicit output formatting (numbered sections) aids parsing

**API Integration:**
- Rate limiting requires upfront user education
- NVD's nested JSON structure needs defensive parsing
- Error states must surface actionable messages

**Python Ecosystem:**
- Virtual environments prevent dependency conflicts
- Type hints improve IDE autocomplete significantly
- Streamlit's caching reduces API costs

## Author

**Kimiya Razdar**
- GitHub: [@Kimiya00](https://github.com/Kimiya00/)
- LinkedIn: [linkedin.com/in/kimiyarazdar](https://www.linkedin.com/in/kimiyarazdar/)
- Portfolio: [kimiya-razdar-portfolio.vercel.app](https://kimiya-razdar-portfolio.vercel.app)

## License

MIT License - see LICENSE file

## Acknowledgments

Built with OpenAI API, NIST National Vulnerability Database, Streamlit, and Plotly.

---

**Note:** This is a research/educational tool. Always verify findings with official security sources before making operational decisions.