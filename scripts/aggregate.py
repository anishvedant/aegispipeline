#!/usr/bin/env python3
"""Normalize scanner output (Checkov, Trivy, Gitleaks, Prowler) into one
findings report with compliance tags. Writes reports/summary.json and
reports/SUMMARY.md. Run from repo root: python3 scripts/aggregate.py"""

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}

# keyword -> framework tags, rough mapping for the report
COMPLIANCE_HINTS = [
    (("encrypt", "sse", "tls", "https"), ["CIS", "PCI DSS 3.4", "HIPAA 164.312(a)(2)(iv)", "GDPR Art. 32"]),
    (("public", "0.0.0.0", "exposed", "internet"), ["CIS", "PCI DSS 1.3", "HIPAA 164.312(e)(1)"]),
    (("iam", "wildcard", "privilege", "policy"), ["CIS", "PCI DSS 7.1", "HIPAA 164.312(a)(1)"]),
    (("secret", "credential", "key", "token", "password"), ["CIS", "PCI DSS 8.2", "GDPR Art. 32"]),
    (("logging", "log", "versioning", "audit"), ["CIS", "PCI DSS 10.2", "HIPAA 164.312(b)"]),
    (("port", "ssh", "rdp", "security group", "nsg"), ["CIS", "PCI DSS 1.2"]),
]


def map_compliance(text):
    text_l = text.lower()
    frameworks = []
    for keywords, tags in COMPLIANCE_HINTS:
        if any(k in text_l for k in keywords):
            for t in tags:
                if t not in frameworks:
                    frameworks.append(t)
    return frameworks or ["CIS"]


def norm(source, severity, resource, title, detail, fix=""):
    sev = (severity or "UNKNOWN").upper()
    if sev not in SEVERITY_ORDER:
        sev = "UNKNOWN"
    return {
        "source": source,
        "severity": sev,
        "resource": resource or "unknown",
        "title": title or "untitled finding",
        "detail": (detail or "")[:500],
        "suggested_fix": fix or "",
        "compliance": map_compliance(f"{title} {detail}"),
    }


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def parse_checkov(findings):
    # severity is often null without a platform key; bump exposure/encryption
    # related checks to HIGH, rest MEDIUM
    data = load_json(REPORTS_DIR / "checkov.json")
    if data is None:
        return
    runs = data if isinstance(data, list) else [data]
    for run in runs:
        failed = (run.get("results") or {}).get("failed_checks", [])
        for c in failed:
            name = c.get("check_name", "")
            sev = c.get("severity")
            if not sev:
                hot = ("public", "encrypt", "0.0.0.0", "wildcard", "*")
                sev = "HIGH" if any(h in name.lower() for h in hot) else "MEDIUM"
            findings.append(norm(
                source="checkov",
                severity=sev,
                resource=c.get("resource"),
                title=f"{c.get('check_id')}: {name}",
                detail=f"File {c.get('file_path')} lines {c.get('file_line_range')}",
                fix=c.get("guideline") or "",
            ))


def parse_trivy(filename, findings):
    data = load_json(REPORTS_DIR / filename)
    if data is None:
        return
    for result in data.get("Results", []) or []:
        target = result.get("Target", "unknown")
        for m in result.get("Misconfigurations", []) or []:
            findings.append(norm(
                source="trivy-config",
                severity=m.get("Severity"),
                resource=target,
                title=f"{m.get('ID')}: {m.get('Title')}",
                detail=m.get("Description", ""),
                fix=m.get("Resolution", ""),
            ))
        for v in result.get("Vulnerabilities", []) or []:
            findings.append(norm(
                source="trivy-image",
                severity=v.get("Severity"),
                resource=f"{target} ({v.get('PkgName')})",
                title=f"{v.get('VulnerabilityID')}: {v.get('Title', v.get('PkgName'))}",
                detail=v.get("Description", ""),
                fix=f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}" if v.get("FixedVersion") else "No fixed version yet",
            ))


def parse_gitleaks(findings):
    # any leak in git history is critical: rotation required, deletion is not enough
    data = load_json(REPORTS_DIR / "gitleaks.json")
    if data is None:
        return
    for leak in data if isinstance(data, list) else []:
        findings.append(norm(
            source="gitleaks",
            severity="CRITICAL",
            resource=leak.get("File"),
            title=f"Secret detected: {leak.get('RuleID')}",
            detail=f"Commit {leak.get('Commit', '')[:8]} line {leak.get('StartLine')}.",
            fix="Rotate the credential, purge from history, move to a secrets manager.",
        ))


def parse_prowler(findings):
    # live account findings outrank code findings
    for path in REPORTS_DIR.glob("prowler*.ocsf.json"):
        data = load_json(path)
        if data is None:
            continue
        for event in data if isinstance(data, list) else []:
            status = (event.get("status_code") or event.get("status") or "").upper()
            if status != "FAIL":
                continue
            sev = event.get("severity") or (event.get("finding_info") or {}).get("severity") or "MEDIUM"
            fi = event.get("finding_info") or {}
            resources = event.get("resources") or [{}]
            findings.append(norm(
                source="prowler-live",
                severity=sev,
                resource=(resources[0] or {}).get("uid", "cloud account"),
                title=fi.get("title", "Live posture finding"),
                detail=fi.get("desc", ""),
                fix=(event.get("remediation") or {}).get("desc", ""),
            ))


def write_markdown(findings, counts):
    lines = [
        "# Security Findings Summary",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Total findings: {len(findings)} "
        f"(Critical {counts['CRITICAL']}, High {counts['HIGH']}, "
        f"Medium {counts['MEDIUM']}, Low {counts['LOW']})",
        "",
        "| Severity | Source | Resource | Finding | Compliance |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(
            f"| {f['severity']} | {f['source']} | {f['resource']} "
            f"| {f['title']} | {', '.join(f['compliance'])} |"
        )
    (REPORTS_DIR / "SUMMARY.md").write_text("\n".join(lines))


def main():
    findings = []
    parse_checkov(findings)
    parse_trivy("trivy-config.json", findings)
    parse_trivy("trivy-image.json", findings)
    parse_gitleaks(findings)
    parse_prowler(findings)

    if not findings:
        print("No scanner output found in reports/. Run the scanners first.")
        sys.exit(0)

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    counts = Counter(f["severity"] for f in findings)

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(findings),
        "by_severity": dict(counts),
        "findings": findings,
    }
    (REPORTS_DIR / "summary.json").write_text(json.dumps(out, indent=2))
    write_markdown(findings, counts)

    print(f"Aggregated {len(findings)} findings from {len(set(f['source'] for f in findings))} scanners.")
    print(f"  Critical: {counts['CRITICAL']}  High: {counts['HIGH']}  Medium: {counts['MEDIUM']}  Low: {counts['LOW']}")


if __name__ == "__main__":
    main()
