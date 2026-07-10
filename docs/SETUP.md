# Setup

Requires: terraform, checkov, trivy, gitleaks, python3. Optional: prowler (live scan), kind + kubectl (admission demo), docker compose (metrics stack).

Scan the staging area:

    checkov -d terraform/deploy --framework terraform --external-checks-dir policies --compact
    trivy config terraform/deploy

Generate the combined report:

    checkov -d terraform/deploy --framework terraform --external-checks-dir policies -o json > reports/checkov.json
    trivy config terraform/deploy --format json --output reports/trivy-config.json
    gitleaks detect --source . --report-format json --report-path reports/gitleaks.json --exit-code 0
    python3 scripts/aggregate.py && python3 scripts/ai_triage.py

Live posture scan (needs AWS credentials configured):

    prowler aws --output-formats json-ocsf --output-directory reports/

Admission demo (needs kind + Kyverno installed):

    kubectl apply -f k8s/policies/grokguard-policies.yaml
    kubectl create namespace model-serving
    kubectl apply -f k8s/workloads/insecure/grok-inference.yaml   # denied
    kubectl apply -f k8s/workloads/secure/grok-inference.yaml     # admitted

AI triage uses the Grok API when XAI_API_KEY is set, local heuristic otherwise.
