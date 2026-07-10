#!/usr/bin/env python3
"""Rank findings from reports/summary.json by blast radius and draft fixes.
Uses the xAI Grok API when XAI_API_KEY is set, otherwise falls back to a
local heuristic so the pipeline works offline. Writes reports/AI_REPORT.md.
Run from repo root: python3 scripts/ai_triage.py"""

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
API_URL = "https://api.x.ai/v1/chat/completions"
MODEL = "grok-3-mini"

SYSTEM_PROMPT = """You are a senior cloud security engineer triaging scanner findings
for a company that trains large AI models. Their crown jewels are model
checkpoints and training data in cloud storage, cloud credentials and API
keys, and GPU cluster infrastructure.

You will receive a JSON list of findings. Respond ONLY with JSON, no
markdown fences, no preamble, in this exact shape:
{
  "ranked_findings": [
    {
      "rank": 1,
      "title": "copy the finding title here",
      "risk_reasoning": "one or two sentences on real world blast radius in THIS company's context",
      "business_impact": "one plain English line an executive would understand",
      "remediation": "a concrete fix, terraform snippet or exact action"
    }
  ],
  "executive_summary": "three sentences max summarizing overall posture"
}"""


def load_findings():
    path = REPORTS_DIR / "summary.json"
    if not path.exists():
        print("reports/summary.json not found. Run scripts/aggregate.py first.")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def call_grok(findings_payload):
    key = os.environ.get("XAI_API_KEY")
    if not key:
        return None
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(findings_payload)},
        ],
        "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read())
        text = data["choices"][0]["message"]["content"]
        text = text.replace("```json", "").replace("```", "").strip()
        return json.loads(text)
    except Exception as e:
        print(f"Grok API call failed ({e}), falling back to local heuristic ranking.")
        return None


def heuristic_rank(findings):
    """Offline fallback: severity-ranked, boosted for exposure, secrets, IAM."""
    boost_terms = ("public", "0.0.0.0", "secret", "credential", "wildcard", "*", "encrypt")
    sev_score = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 10, "UNKNOWN": 10}

    def score(f):
        s = sev_score.get(f["severity"], 10)
        text = (f["title"] + f["detail"]).lower()
        if any(t in text for t in boost_terms):
            s += 20
        if f["source"] in ("gitleaks", "prowler-live"):
            s += 15
        return s

    ranked = sorted(findings, key=score, reverse=True)
    out = []
    for i, f in enumerate(ranked, 1):
        text = (f["title"] + f["detail"]).lower()
        if "secret" in text or f["source"] == "gitleaks":
            impact = "A leaked credential lets an outsider walk in the front door, no exploit needed."
            reason = "Credentials in git history are permanently compromised and directly usable."
        elif "public" in text or "0.0.0.0" in text:
            impact = "Data or systems reachable by anyone on the internet, including model artifacts."
            reason = "Public exposure of storage or management ports is the most common real breach path."
        elif "wildcard" in text or "iam" in text:
            impact = "One compromised identity could control the entire cloud account."
            reason = "Star on star IAM turns any single credential theft into full account takeover."
        elif "encrypt" in text or "tls" in text:
            impact = "Data at rest or in transit is readable if any other control fails."
            reason = "Missing encryption removes the safety net behind every other layer."
        else:
            impact = "Weakens overall posture and audit standing."
            reason = "Contributes to configuration drift and compliance gaps."
        out.append({
            "rank": i,
            "title": f["title"],
            "risk_reasoning": reason,
            "business_impact": impact,
            "remediation": f.get("suggested_fix") or "See the hardened example in terraform/*/secure/",
        })
    return {
        "ranked_findings": out,
        "executive_summary": (
            f"{len(findings)} findings across code and live posture scans. "
            "Highest risk items involve public exposure, credentials, and over permissive IAM. "
            "Fixes exist for every finding in the hardened Terraform set."
        ),
    }


def write_report(result, mode):
    lines = [
        "# AegisPipeline AI Triage Report",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} (mode: {mode})",
        "",
        "## Executive summary",
        "",
        result.get("executive_summary", ""),
        "",
        "## Findings ranked by real world risk",
        "",
    ]
    for f in result.get("ranked_findings", []):
        lines += [
            f"### {f['rank']}. {f['title']}",
            "",
            f"Why it matters here: {f['risk_reasoning']}",
            "",
            f"Business impact: {f['business_impact']}",
            "",
            f"Fix: {f['remediation']}",
            "",
        ]
    (REPORTS_DIR / "AI_REPORT.md").write_text("\n".join(lines))


def main():
    data = load_findings()
    findings = data["findings"]

    # cap payload size
    payload = findings[:40]

    result = call_grok(payload)
    mode = "grok"
    if result is None:
        result = heuristic_rank(findings)
        mode = "local-heuristic"

    write_report(result, mode)
    print(f"Wrote {REPORTS_DIR / 'AI_REPORT.md'} using {mode} ranking of {len(findings)} findings.")


if __name__ == "__main__":
    main()
