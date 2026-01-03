import streamlit as st
import requests
import json

# Set page config
st.set_page_config(
    page_title="Agentic Risk Analysis",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for aesthetics
st.markdown("""
<style>
    .reportview-container {
        background: #f0f2f6;
    }
    .metric-card {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        text-align: center;
    }
    .stAlert {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Agentic Risk Analysis Dashboard")
st.markdown("Enter a CVE ID to trigger the **AI Agent** which performs real-time threat intelligence gathering and risk assessment.")

# Input Section
cve_id = st.text_input("Enter CVE ID (e.g., CVE-2021-44228)", value="CVE-2021-44228")

if st.button("Analyze Vulnerability", type="primary"):
    with st.spinner(f"🔍 Agent is analyzing {cve_id}... (Gathering Intel, Checking GitHub, Querying AI)"):
        try:
            # Call the FastAPI backend (assuming it's running locally)
            # For simplicity in this demo, we can also import the agent directly if they share the env,
            # but using HTTP follows the plan.
            API_URL = "http://127.0.0.1:8000/analyze"
            
            # NOTE: We are running both in the same env for this demo, 
            # so we'll try to connect to the separate process.
            try:
                response = requests.post(API_URL, json={"cve_id": cve_id}, timeout=120)
                if response.status_code == 200:
                    data = response.json()
                else:
                    st.error(f"API Error: {response.text}")
                    data = None
            except requests.exceptions.ConnectionError:
                # Fallback: Run logic directly if API isn't up (for easier verification)
                st.warning("⚠️ API not reachable. Running local agent instance...")
                from src.agent import RiskAnalysisAgent
                agent = RiskAnalysisAgent()
                tree = agent.analyze(cve_id)
                data = json.loads(tree.to_json())

            if data:
                # --- Dashboard Layout ---
                
                # Top Row: Key Metrics
                col1, col2, col3, col4, col5 = st.columns(5)
                
                severity = data.get("severity", "UNKNOWN")
                ssvc_data = data.get("ssvc", {})
                ssvc_decision = ssvc_data.get("decision", "Track")
                
                rbp_score = data.get("rbp_score", 0.0)
                comp_prob = data.get("threat", {}).get("likelihood", {}).get("composite_prob", 0.0)
                lev_prob = data.get("lev", {}).get("probability", 0.0)
                
                with col1:
                    st.metric("RBP Score", f"{rbp_score:.1f}/100", help="Unified Risk-Based Prioritization Score")
                with col2:
                    st.metric("Severity", severity)
                with col3:
                    # Color code SSVC
                    color = "off"
                    if ssvc_decision == "Act": color = "inverse"
                    st.metric("SSVC Decision", ssvc_decision, help="Stakeholder-Specific Vulnerability Categorization")
                with col4:
                    st.metric("Composite Prob", f"{comp_prob:.2%}", help="max(EPSS, KEV, LEV)")
                with col5:
                    st.metric("NIST LEV", f"{lev_prob:.4f}", help="Likely Exploited Vulnerability (Past Probability)")

                st.divider()
                
                # Second Row: Detailed Status
                c1, c2, c3, c4 = st.columns(4)
                cisa_kev = data.get("threat", {}).get("likelihood", {}).get("known_evidence", {}).get("cisa_kev", False)
                exploit_status = ssvc_data.get("exploitation_status", "None")
                tech_impact = ssvc_data.get("technical_impact", "Low")
                temporal_e = data.get("temporal_e", "NOT_DEFINED")
                
                with c1:
                    status = "✅ No"
                    if cisa_kev: status = "🚨 YES"
                    st.metric("CISA KEV", status)
                with c2:
                    st.metric("Exploitation Status", exploit_status)
                with c3:
                    st.metric("Technical Impact", tech_impact)
                with c4:
                    st.metric("CVSS Temporal E", temporal_e)
                    
                st.divider()

                # Middle Row: AI Analysis
                st.header("🤖 AI Analyst Report")
                ai_analysis = data.get("ai_analysis", "No analysis provided.")
                
                with st.container():
                     st.info(ai_analysis)

                st.divider()

                # Bottom Row: Detailed Tree
                with st.expander("📂 View Full Risk Tree (JSON)"):
                    st.json(data)

        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")
