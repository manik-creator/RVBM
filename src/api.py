from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .agent import RiskAnalysisAgent

app = FastAPI(title="Risk Analysis API", version="1.0")

class AnalysisRequest(BaseModel):
    cve_id: str

@app.get("/")
def health_check():
    return {"status": "ok", "service": "Risk Analysis Agent"}

@app.post("/analyze")
def analyze_cve(request: AnalysisRequest):
    """
    Analyzes a CVE ID using the full agentic pipeline (Collectors + AI).
    """
    try:
        agent = RiskAnalysisAgent()
        # Analyze returns the VulnerabilityRiskTree object
        tree = agent.analyze(request.cve_id)
        
        # Convert to dictionary using to_dict or standard json dump
        # Since tree.to_json() returns a string, we parse it back to dict
        import json
        return json.loads(tree.to_json())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
