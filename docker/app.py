"""Minimal triage API. Accepts findings, returns them severity-ranked."""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="aegis-triage-api")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class Finding(BaseModel):
    title: str
    severity: str = "MEDIUM"
    resource: str = "unknown"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/rank")
def rank(findings: list[Finding]):
    ranked = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity.upper(), 4))
    return {"count": len(ranked), "ranked": ranked}
