from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
import os
import requests
import json
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from dotenv import load_dotenv

# ==========================================
# CONFIGURATION & CONNECTIONS
# ==========================================
load_dotenv()

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
es = Elasticsearch(ES_URL)

app = FastAPI(
    title="APT SIEM Central Hub",
    description="Unified API for Alert Ingestion, AI Triage, and Threat Timelines.",
    version="2.0"
)

# ==========================================
# CORS CONFIGURATION
# ==========================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# DATA MODELS
# ==========================================
class AlertRequest(BaseModel):
    alert_data: dict
    provider: str = Field(default="gemini", description="e.g., gemini, openai, nvidia")
    model: str = Field(default="gemini-1.5-flash", description="The specific model string for the provider")
    api_key: Optional[str] = Field(default=None, description="Optional: Pass the API key directly from the frontend.")


class BulkAlertRequest(BaseModel):
    module_source: str
    alerts: list[dict]


class UnifiedAlert(BaseModel):
    module_source: str
    alert_data: Dict[str, Any]


# ==========================================
# 1. AI ADVISORY ENDPOINT
# ==========================================
def get_api_key(provider: str, user_provided_key: str = None) -> str:
    if user_provided_key:
        return user_provided_key

    env_mapping = {
        "gemini": "GEMINI_API_KEY",
        "openai": "OPENAI_API_KEY",
        "nvidia": "NVIDIA_API_KEY"
    }

    env_var_name = env_mapping.get(provider.lower())
    if not env_var_name:
        return None

    key = os.environ.get(env_var_name)
    if key and not key.startswith("YOUR_"):
        return key

    return None


def call_llm_api(prompt: str, provider: str, model_name: str, user_api_key: str = None) -> str:
    provider = provider.lower()
    api_key = get_api_key(provider, user_api_key)

    if not api_key:
        raise HTTPException(status_code=401,
                            detail=f"Missing valid API key for {provider}. Provide it in the UI or set the environment variable.")

    try:
        if provider == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            response = requests.post(url, headers={"Content-Type": "application/json"}, json=payload)
            if not response.ok:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            return response.json()['candidates'][0]['content']['parts'][0]['text']

        elif provider == "openai":
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
            payload = {"model": model_name, "messages": [{"role": "user", "content": prompt}]}
            response = requests.post(url, headers=headers, json=payload)
            if not response.ok:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            return response.json()['choices'][0]['message']['content']

        elif provider == "nvidia":
            url = "https://integrate.api.nvidia.com/v1/chat/completions"
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
            payload = {"model": model_name, "messages": [{"role": "user", "content": prompt}], "max_tokens": 1024}
            response = requests.post(url, headers=headers, json=payload)
            if not response.ok:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            return response.json()['choices'][0]['message']['content']
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported provider '{provider}'")

    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"LLM API Network Error: {str(e)}")
    except KeyError as e:
        raise HTTPException(status_code=502, detail=f"LLM API Parsing Error: {str(e)}")


@app.post("/api/v1/analyze")
async def analyze_alert(req: AlertRequest):
    alert = req.alert_data

    # Send the raw evidence alongside the alert to ensure accuracy and reduce False Positives!
    prompt = f"""
    You are an Expert Tier 3 Security Operations Center (SOC) Analyst.
    Review the following SIEM alert in Vietnamese:
    {json.dumps(alert, indent=2)}

    1. Threat Summary: Explain what the attacker is doing based on the evidence.
    2. Evidence Evaluation: Interpret the ML scores, rule hits, and specifically analyze the 'raw_evidence' URIs to verify if this is a true attack or a false positive.
    3. Remediation Steps: Provide 2 immediate commands to stop this threat.
    """

    analysis = call_llm_api(prompt, req.provider, req.model, req.api_key)
    return {"status": "success", "alert_id": alert.get("alert_id"), "analysis": analysis}


# ==========================================
# 2. UNIFIED INGESTION ENDPOINTS
# ==========================================
@app.post("/api/v1/ingest")
async def ingest_alert(payload: UnifiedAlert):
    safe_module_name = payload.module_source.lower().replace("_", "-")
    index_name = f"apt-{safe_module_name}-alerts"
    doc = payload.alert_data
    if "timestamp" not in doc:
        doc["timestamp"] = datetime.utcnow().isoformat() + "Z"
    try:
        res = es.index(index=index_name, document=doc)
        return {"status": "success", "index": index_name, "document_id": res["_id"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database Ingestion Failed: {str(e)}")


@app.post("/api/v1/ingest/bulk")
async def ingest_bulk_alerts(payload: BulkAlertRequest):
    safe_module_name = payload.module_source.lower().replace("_", "-")
    index_name = f"apt-{safe_module_name}-alerts"
    actions = []
    for alert in payload.alerts:
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.utcnow().isoformat() + "Z"
        actions.append({
            "_index": index_name,
            "_source": alert
        })
    try:
        success, failed = bulk(es, actions)
        return {"status": "success", "indexed": success, "failed": failed}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bulk Ingestion Failed: {str(e)}")


# ==========================================
# 3. TIMELINE RECONSTRUCTION ENDPOINT
# ==========================================
@app.get("/api/v1/timeline/{ip}")
async def get_timeline(ip: str):
    try:
        query = {
            "query": {"term": {"entity.source_ip.keyword": ip}},
            "sort": [{"timestamp": {"order": "asc"}}],
            "size": 50
        }
        res = es.search(index="apt-*-alerts", body=query, ignore_unavailable=True)
        timeline = []
        for hit in res["hits"]["hits"]:
            source = hit["_source"]
            timeline.append({
                "timestamp": source.get("timestamp"),
                "module": source.get("module_source", "Unknown"),
                "severity": source.get("threat_classification", {}).get("severity", "Unknown"),
                "tactic": source.get("threat_classification", {}).get("mitre_tactic", "Unknown"),
                "alert_id": source.get("alert_id", "Unknown")
            })
        return {"target_ip": ip, "total_events": len(timeline), "timeline": timeline}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Timeline Query Failed: {str(e)}")


@app.get("/api/v1/alerts")
async def get_recent_alerts(limit: int = 50):
    try:
        query = {
            "query": {"match_all": {}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": limit
        }
        res = es.search(index="apt-*-alerts", body=query, ignore_unavailable=True)
        alerts = [hit["_source"] for hit in res["hits"]["hits"]]
        return {"status": "success", "total": len(alerts), "alerts": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database Query Failed: {str(e)}")


@app.get("/health")
async def health_check():
    es_status = "online" if es.ping() else "offline"
    return {"status": "online", "elasticsearch": es_status}