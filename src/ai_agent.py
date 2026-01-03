import os
import json
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_community.tools.tavily_search import TavilySearchResults
from langgraph.graph import StateGraph, END
from typing import TypedDict, Annotated, List
import operator
from dotenv import load_dotenv

# Load env variables (API keys)
load_dotenv()

# Define the state for our agent
class AgentState(TypedDict):
    cve_data: str # The JSON string of the tree
    analysis: str
    messages: Annotated[List[dict], operator.add]

class AXRiskAgent:
    def __init__(self):
        # Initialize LLM
        # Using Llama3-70b-8192 via Groq for reasoning
        self.llm = ChatGroq(
            temperature=0, 
            groq_api_key=os.getenv("GROQ_API_KEY"), 
            model_name="llama-3.3-70b-versatile"
        )
        self.search = TavilySearchResults(max_results=3)

    def _analyst_node(self, state: AgentState):
        """
        The Analyst reasoning node. It looks at the existing data and supplemental search results.
        """
        cve_json = state["cve_data"]
        cve_dict = json.loads(cve_json)
        cve_id = cve_dict.get("cve_id", "Unknown CVE")
        
        # 1. Research for Patches/Mitigations/Controls
        print(f"    [AI] Researching Vendor-Specific Defenses (CrowdStrike, Tenable, Splunk, WAF) for {cve_id}...")
        search_query = f"{cve_id} CrowdStrike detection Tenable Nessus plugin Splunk query Palo Alto signature WAF rule"
        search_results = self.search.invoke(search_query)
        
        # 2. Analyze with Context
        system_prompt = (
            "You are an elite Cyber Threat Intelligence Analyst. "
            "You have been given a structured risk tree AND web search results for a specific CVE. "
            "The tree includes CISA SSVC (Stakeholder-Specific Vulnerability Categorization) decision and NIST LEV (Likely Exploited Vulnerabilities) data.\n\n"
            "Your job is to provide a concise, high-impact Executive Summary and Technical Recommendation.\n\n"
            
            "STRUCTURE YOUR RESPONSE EXACTLY AS FOLLOWS:\n"
            "**Executive Summary:**\n"
            "<Status on Exploitation (CISA/EPSS). Mention the SSVC Decision (Act/Attend/Track).>\n\n"
            
            "**Technical Recommendation:**\n"
            "<Final verdict based on SSVC: ACT/ATTEND/TRACK.>\n\n"
            
            "**Patch Details & Mitigations:**\n"
            "<Specific versions to upgrade to. Workarounds.>\n\n"
            
            "**Vendor-Specific Security Controls:**\n"
            "Map findings to specific security vendors where possible. Use the format:\n"
            "* **[Vendor Name]**: [Specific Rule/Plugin/Signature ID] ([Reference URL])\n"
            "  * Example: **CrowdStrike**: Falcon Prevent 'Suspicious Process' (https://www.crowdstrike.com/...)\n"
            "  * Example: **Tenable/Nessus**: Plugin ID 156000 (https://www.tenable.com/...)\n"
            "If exact IDs aren't found, suggest the *type* of sensor/policy needed.\n"
            "**IMPORTANT**: You MUST include the source URL from the search results for every vendor claim."
        )
        
        user_content = f"""
        CVE Data: {cve_json}
        
        Search Results:
        {json.dumps(search_results, indent=2)}
        """
        
        response = self.llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_content)
        ])
        
        return {"analysis": response.content}

    def run(self, cve_tree_json: str) -> str:
        # Build the graph
        workflow = StateGraph(AgentState)
        
        workflow.add_node("analyst", self._analyst_node)
        workflow.set_entry_point("analyst")
        workflow.add_edge("analyst", END)
        
        app = workflow.compile()
        
        # Execute
        result = app.invoke({"cve_data": cve_tree_json, "messages": []})
        return result["analysis"]

if __name__ == "__main__":
    # Test
    sample_json = '{"cve_id": "CVE-TEST", "severity": "HIGH"}'
    agent = AXRiskAgent()
    print(agent.run(sample_json))
