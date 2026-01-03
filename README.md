# Agentic AI Risk Prioritization Engine 🛡️

An advanced Cybersecurity Risk Analysis application that implements the "Risk Based Prioritization" (RBP) methodology. It moves beyond simple CVE lookups to provide mathematically grounded, actionable prioritization using CISA KEV, EPSS, NIST LEV, and SSVC Decision Trees.

## Core Features

- **Unified RBP Score (0-100)**: A weighted score combining impact (CVSS) and likelihood (Composite Probability).
- **Composite Exploitation Probability**: Real-time calculation of $P_{comp} = max(EPSS, KEV, LEV)$.
- **SSVC Decision Trees**: 4-tier Stakeholder-Specific Vulnerability Categorization (Act, Attend, Track Closely, Track).
- **NIST LEV (Likely Exploited Vulnerabilities)**: Probabilistic backward-looking metric for historical exploitation.
- **AI Analyst (Groq/Llama-3)**: Generates executive summaries and vendor-specific defense recommendations (Tenable, CrowdStrike, WAF rules).
- **Web UI & API**: Modern dashboard built with Streamlit and FastAPI.

## Setup & Installation

### 1. Prerequisites
- Python 3.10+
- `uv` (recommended) or `pip`

### 2. Install Dependencies
```bash
uv sync
```

### 3. Environment Variables
Create a `.env` file in the root directory:
```env
GROQ_API_KEY=your_key_here
TAVILY_API_KEY=your_key_here
```

## Running the Application

### Option 1: Web Dashboard (Recommended)
This runs both the backend API and the frontend UI.
```bash
# Terminal 1: Start FastAPI
uv run uvicorn src.api:app --port 8000

# Terminal 2: Start Streamlit
uv run streamlit run streamlit_app.py
```

### Option 2: Command Line Interface (CLI)
Quick single-CVE analysis with Rich formatting.
```bash
uv run python main.py CVE-2021-44228
```

### Option 3: Bulk Verification Script
Run the verification engine against multiple CVEs.
```bash
export PYTHONPATH=$PYTHONPATH:.
uv run python tests/bulk_test.py
```

## Verification: 15 Diverse CVE Bulk Test Results

The engine was verified against a set of 15 CVEs to ensure "wedge-shaped" prioritization accuracy.

| CVE ID | RBP Score | SSVC Priority | Comp. Prob | KEV | LEV | Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2021-44228** | **100.0** | **Act (1)** | 1.00 | Yes | 0.62 | Patch Immediately (Log4Shell) |
| **CVE-2023-23397** | **98.0** | **Act (1)** | 1.00 | Yes | 0.61 | Patch Immediately (Outlook) |
| **CVE-2024-21413** | **98.0** | **Act (1)** | 1.00 | Yes | 0.61 | Patch Immediately |
| **CVE-2021-34473** | **91.0** | **Act (1)** | 1.00 | Yes | 0.62 | Patch Immediately (ProxyShell) |
| **CVE-2024-38063** | **88.2** | **Act (1)** | 0.90 | No | 0.60 | High Priority (Win TCP/IP) |
| **CVE-2017-0144** | **88.0** | **Act (1)** | 1.00 | Yes | 0.62 | Patch Immediately (EternalBlue) |
| **CVE-2022-30190** | **78.0** | **Act (1)** | 1.00 | Yes | 0.61 | High Priority (Follina) |
| **CVE-2014-0160** | **75.0** | **Act (1)** | 1.00 | Yes | 0.62 | Historical weaponization |
| **CVE-2020-1472** | **55.0** | **Act (1)** | 1.00 | Yes | 0.62 | Active (Zerologon) |
| **CVE-2024-21406** | **0.9** | **Track Closely (3)** | 0.01 | No | 0.01 | Low Likelihood |
| **CVE-1999-0524** | **0.0** | **Track (4)** | 0.00 | No | 0.00 | Legacy Info item |

## Project Structure

- `src/collectors/`: Data gathering from NVD, CISA, EPSS, First.org.
- `src/analysis/`: RBP Scoring, SSVC Decision Trees, and LEV logic.
- `src/ai_agent.py`: LangGraph-based AI analyst orchestration.
- `streamlit_app.py`: Modern Streamlit dashboard.
- `main.py`: CLI Entrypoint.
