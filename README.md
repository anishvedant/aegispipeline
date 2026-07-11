# AegisPipeline

[![Security Gate](https://github.com/anishvedant/aegispipeline/actions/workflows/security.yml/badge.svg)](https://github.com/anishvedant/aegispipeline/actions/workflows/security.yml)

AegisPipeline is a cloud and Kubernetes security automation lab that demonstrates how an infrastructure security team can scan infrastructure before deployment, validate live AWS posture after deployment, enforce Kubernetes guardrails at admission time, and retain evidence for review.

The project combines Terraform, AWS, Checkov, Trivy, Gitleaks, Prowler, K3s, Kubernetes, Kyverno, Python reporting scripts, Docker, Prometheus, Grafana, and GitHub Actions.

## Project goal

Cloud and Kubernetes incidents often begin with configuration mistakes rather than sophisticated exploits. Common examples include public object storage, wildcard IAM permissions, exposed administrative ports, committed credentials, privileged containers, mutable image tags, and workloads with no resource controls.

AegisPipeline turns those risks into automated controls:

1. Scan infrastructure and application artifacts before deployment.
2. Deploy a hardened AWS baseline through Terraform.
3. Scan the live AWS account with Prowler.
4. Normalize findings into one report.
5. Prioritize findings using Grok when configured, or a deterministic offline heuristic.
6. Enforce Kubernetes workload policy with Kyverno.
7. Prove that an insecure workload is blocked and a hardened workload is admitted.

## Architecture

```text
Developer push or pull request
              |
              v
+----------------------------------------------------------+
| GitHub Actions                                           |
|                                                          |
| Checkov   Blocking IaC policy gate                       |
| Gitleaks  Blocking full-history secrets gate             |
| Trivy     Secondary IaC and image visibility             |
+----------------------------------------------------------+
              |
              v
      Hardened Terraform staging
              |
              v
+----------------------------------------------------------+
| AWS deployment                                           |
|                                                          |
| S3 model-artifact bucket                                 |
| Public-access block, encryption, versioning              |
| Restricted security group                                |
| Least-privilege IAM policy                               |
+----------------------------------------------------------+
              |
              v
       Prowler live AWS posture scan
              |
              v
  aggregate.py -> summary.json and SUMMARY.md
              |
              v
  ai_triage.py -> AI_REPORT.md
              |
              v
+----------------------------------------------------------+
| AWS EC2 single-node K3s cluster                          |
|                                                          |
| Kyverno admission controller                            |
| GrokGuard ClusterPolicies                               |
| Insecure workload denied                                |
| Hardened workload admitted                              |
+----------------------------------------------------------+
```

## Three security layers

### 1. Pre-deployment security

Infrastructure code and application artifacts are checked before they are trusted:

- **Checkov** scans Terraform and Kubernetes configuration, including the custom ownership-tag policy in `policies/`.
- **Gitleaks** scans the complete Git history for tokens, private keys, and other credentials.
- **Trivy** provides a second opinion on Terraform and Kubernetes misconfiguration and scans the hardened Docker image for operating-system and library vulnerabilities.

In the current lab workflow, Checkov and Gitleaks are blocking controls. Trivy produces review artifacts without blocking the branch, which avoids making the portfolio branch depend on transient upstream image findings. A production rollout can change Trivy `exit-code` to `1` after establishing an approved vulnerability baseline and exception process.

### 2. Live AWS posture validation

Terraform deploys the hardened staging configuration from `terraform/deploy/`. Prowler then scans the real AWS account and exports OCSF JSON plus compliance-oriented CSV reports. This distinguishes static code review from runtime cloud posture management.

### 3. Kubernetes admission enforcement

Terraform provisions a lightweight K3s Kubernetes cluster on an AWS EC2 instance. Kyverno runs inside that cluster as an admission controller. Before Kubernetes admits a workload, Kyverno checks it against GrokGuard policies.

The policies block:

- `hostPath` volumes
- privileged containers
- containers that do not declare non-root execution
- images using the mutable `:latest` tag
- containers without CPU and memory limits

The intentionally insecure workload is denied. The hardened workload is admitted and reaches `1/1 Running`.

## What was deployed

| Layer | Deployed or implemented |
|---|---|
| AWS secure baseline | S3 model-artifact bucket, AES-256 server-side encryption, versioning, public-access block, ownership tags, restricted security group, least-privilege S3 read policy |
| AWS posture | Prowler account scan exported as JSON-OCSF and compliance CSV files |
| Kubernetes infrastructure | Single-node K3s control plane on EC2, Elastic IP, encrypted GP3 root volume, IMDSv2, SSH and Kubernetes API restricted to the administrator CIDR |
| Admission control | Kyverno with three GrokGuard ClusterPolicies |
| Workload test | Intentionally insecure model-serving deployment denied, hardened deployment admitted |
| Reporting | Normalized JSON and Markdown summaries, risk-ranked triage report, Kubernetes enforcement evidence |
| Optional monitoring | Prometheus exporter and Grafana/Prometheus Docker Compose stack |
| Multi-cloud fixtures | Secure and insecure AWS and Azure Terraform examples, Azure was not deployed during the recorded lab run |

## Repository layout

```text
.github/workflows/
  security.yml             Main Terraform, secret, and container security workflow
  security-k8s.yml         Kubernetes manifest visibility workflow

docker/
  app.py                   Minimal FastAPI finding-ranking service
  Dockerfile               Hardened image, pinned dependencies, non-root execution
  Dockerfile.insecure      Deliberately weak image for scanner testing

docs/
  SETUP.md                 Complete setup, deployment, verification, and teardown guide

k8s/
  policies/                Kyverno GrokGuard ClusterPolicies
  workloads/insecure/      Deliberately non-compliant deployment
  workloads/secure/        Hardened deployment that passes GrokGuard

monitoring/
  security_exporter.py     Converts summary.json into Prometheus metrics
  prometheus.yml           Scrapes the exporter every 15 seconds
  docker-compose.yml       Local Prometheus and Grafana stack

policies/
  require_project_tag.yaml Custom Checkov ownership-tag rule

reports/
  SUMMARY.md               Aggregated scanner findings
  AI_REPORT.md             Risk-prioritized findings and drafted remediation
  compliance/              Prowler compliance exports
  k8s/                     Live Kubernetes node, policy, event, denial, and workload evidence

scripts/
  aggregate.py             Normalizes Checkov, Trivy, Gitleaks, and Prowler output
  ai_triage.py             Grok-enabled or offline heuristic risk ranking

terraform/
  aws/insecure/            Deliberately insecure AWS fixture
  aws/secure/              Hardened AWS fixture
  aws/k3s-cluster/         EC2-based K3s cluster
  azure/insecure/          Deliberately insecure Azure fixture
  azure/secure/            Hardened Azure fixture
  deploy/                  Controlled Terraform deployment staging area
```

## Core components

### Terraform

Terraform is the infrastructure builder. It runs from the operator workstation and calls AWS APIs to create or remove resources. The project keeps insecure fixtures separate from the controlled `terraform/deploy/` staging directory so intentionally vulnerable examples are not applied accidentally.

The secure AWS baseline includes:

- Globally unique S3 bucket naming through `random_id`
- S3 public-access blocking
- S3 versioning
- AES-256 server-side encryption
- SSH restricted to an administrator `/32` CIDR
- HTTPS-only outbound access in the demo security group
- An IAM policy limited to `s3:GetObject` and `s3:ListBucket` on one bucket
- Project and environment ownership tags

### Prowler

Prowler performs the live Cloud Security Posture Management scan. The recorded run executed 610 AWS checks. The aggregated project report contained 367 findings from three scanner sources, categorized as 4 critical, 98 high, 144 medium, and 121 low.

Prowler scans the complete AWS account, not only resources created by AegisPipeline. Therefore, its findings represent account-wide posture, existing services, and the lab resources together.

### `scripts/aggregate.py`

The aggregation script reads available Checkov, Trivy, Gitleaks, and Prowler outputs. It converts different JSON structures into one normalized finding model with source, severity, resource, title, detail, remediation guidance, and lightweight compliance tags.

It writes:

- `reports/summary.json`, machine-readable output
- `reports/SUMMARY.md`, GitHub-readable output

### `scripts/ai_triage.py`

The triage layer is Grok-enabled, but Grok is optional.

- If `XAI_API_KEY` is set, up to 40 normalized findings are sent to the xAI chat-completions API for blast-radius ranking and remediation drafting.
- If no key is present, or the API call fails, the script uses a deterministic local heuristic that prioritizes severity, public exposure, secrets, broad IAM, encryption gaps, live Prowler findings, and Gitleaks findings.

The committed lab report was generated in `local-heuristic` mode. No xAI key is required to reproduce the project, and no API key should ever be committed.

### Docker

`docker/app.py` is a minimal FastAPI service with a health endpoint and a finding-ranking endpoint. The hardened Dockerfile uses a current slim Python base, pinned dependencies, and non-root execution. GitHub Actions builds the image and Trivy scans it.

The deliberately insecure Dockerfile exists only as a scan fixture. It uses an old base and lacks non-root hardening.

### Kubernetes and GrokGuard

The K3s cluster runs on AWS EC2. Kyverno evaluates incoming Pods and generated Pod templates from Deployments.

The three ClusterPolicies are:

| Policy | Purpose |
|---|---|
| `gg-block-hostpath` | Prevents workloads from mounting the node filesystem or model-checkpoint paths |
| `gg-pod-hardening` | Blocks privileged execution and requires non-root containers |
| `gg-supply-chain-and-limits` | Blocks `:latest` images and requires CPU and memory limits |

This is preventive control, not only detection. The rejected workload never reaches a running state.

### Monitoring

`monitoring/security_exporter.py` reads `reports/summary.json` and exposes:

- `grokguard_findings_total{severity}`
- `grokguard_findings_by_source{source}`
- `grokguard_last_scan_timestamp`

Prometheus can scrape the exporter on port `9105`, and Grafana can visualize findings alongside operational metrics. This monitoring stack is an optional extension and was not required to prove the core AWS and Kubernetes controls.

## GitHub Actions behavior

The main workflow runs on pushes and pull requests targeting `main`.

Blocking controls:

- Checkov fails on unaccepted high or critical Terraform findings.
- Gitleaks fails when credentials or secrets are detected in Git history.

Visibility controls:

- Trivy Terraform scan produces a JSON artifact.
- Trivy Docker image scan produces a JSON artifact.
- Kubernetes Checkov and Trivy workflows report against the hardened workload, while Kyverno remains the authoritative runtime enforcement point.

The Checkov gate explicitly documents six accepted lab-only gaps:

- `CKV2_AWS_5`, the demo security group is not attached to an EC2 training node
- `CKV2_AWS_62`, S3 event notifications are outside the lab scope
- `CKV2_AWS_61`, S3 lifecycle automation is outside the lab scope
- `CKV_AWS_18`, S3 access logging requires a separate log destination
- `CKV_AWS_144`, cross-region replication requires additional regional infrastructure
- `CKV_AWS_145`, the lab uses S3-managed AES-256 encryption rather than a customer-managed KMS key

These exceptions are explicit and reviewable. They are not hidden claims that the lab is production-ready.

## Live evidence from the lab

Use these files to verify the completed run:

- [`reports/SUMMARY.md`](reports/SUMMARY.md), aggregated findings
- [`reports/AI_REPORT.md`](reports/AI_REPORT.md), risk-prioritized triage output
- [`reports/k8s/insecure-workload-blocked.txt`](reports/k8s/insecure-workload-blocked.txt), Kyverno denial evidence
- [`reports/k8s/model-serving.txt`](reports/k8s/model-serving.txt), hardened deployment and Pod running
- [`reports/k8s/clusterpolicies.txt`](reports/k8s/clusterpolicies.txt), GrokGuard policies ready
- [`reports/k8s/kyverno-pods.txt`](reports/k8s/kyverno-pods.txt), Kyverno controllers running
- [`reports/k8s/nodes.txt`](reports/k8s/nodes.txt), live K3s node evidence
- [`reports/k8s/events.txt`](reports/k8s/events.txt), namespace event history

## Demo path

A short interview demonstration should follow this order:

1. Open `reports/k8s/insecure-workload-blocked.txt` and show why the unsafe deployment was denied.
2. Open `reports/k8s/model-serving.txt` and show the hardened workload at `1/1 Running`.
3. Open `reports/k8s/clusterpolicies.txt` and show all GrokGuard policies ready.
4. Open `reports/SUMMARY.md` and explain how multiple scanner formats were normalized.
5. Open `reports/AI_REPORT.md` and explain the risk-prioritization layer.
6. Optionally show `.github/workflows/security.yml` to explain automated pre-deployment checks.

## Quick start

The complete setup, deployment, verification, and teardown procedure is in [`docs/SETUP.md`](docs/SETUP.md).

Basic local comparison:

```bash
cp terraform/aws/insecure/main.tf terraform/deploy/main.tf
checkov -d terraform/deploy --framework terraform --external-checks-dir policies --compact

cp terraform/aws/secure/main.tf terraform/deploy/main.tf
checkov -d terraform/deploy --framework terraform --external-checks-dir policies --compact
```

Do not apply the insecure fixture. Only apply the controlled hardened staging configuration.

## Security design decisions

- Two IaC scanners provide broader visibility because scanner engines have different coverage and rule implementations.
- Gitleaks checks full Git history because deleting a secret from the current file does not invalidate a credential that was previously committed.
- Terraform plans, state, kubeconfig files, private keys, environment files, and VPN profiles are excluded from Git.
- Terraform dependency lock files are retained for provider reproducibility.
- The Grok integration has an offline fallback, so report generation does not depend on an external API.
- Runtime admission enforcement protects against manual `kubectl` changes, compromised automation, and emergency changes that bypass CI.
- The project stores evidence so control effectiveness can be reviewed without rebuilding the lab.

## Business value

AegisPipeline demonstrates how infrastructure security can support engineering velocity rather than become a final manual bottleneck.

The control model can reduce:

- Repeated manual review of common configuration mistakes
- Late-stage rework after resources are already deployed
- Exposure caused by public storage or broad IAM permissions
- Credential leakage through source control
- Kubernetes node risk from privileged or host-mounted workloads
- Reliability and cost risk from workloads with no CPU or memory limits
- Audit effort by retaining repeatable evidence

No fixed financial saving is claimed because the lab did not measure a production environment. The value comes from earlier feedback, repeatable enforcement, reduced incident likelihood, and more efficient use of security engineering time.

## Known limitations

This is a focused lab and portfolio build, not a production platform.

Current limitations include:

- Long-lived IAM user credentials were used for the lab instead of federation.
- Terraform state is local rather than stored in a remote encrypted backend with locking.
- K3s is a single-node cluster, not highly available managed Kubernetes.
- The EC2 control plane is internet-reachable from one restricted administrator CIDR instead of being private behind a controlled access path.
- Prowler aggregation can be improved with stronger deduplication and richer status parsing.
- The Docker API is a demonstration service, not a production triage platform.
- Trivy findings are report-only in the portfolio workflow until a stable vulnerability baseline and exception process are established.
- The monitoring folder provides the components for Prometheus and Grafana, but no committed dashboard is included yet.
- Azure fixtures are implemented but were not deployed during the recorded run.

## Production roadmap

A production implementation would add:

- GitHub OIDC or workforce federation with short-lived cloud credentials
- Least-privilege deployment and scanning roles
- Remote encrypted Terraform state with locking and controlled access
- EKS, AKS, or another managed Kubernetes service with private endpoints
- Centralized CloudTrail, VPC Flow Logs, GuardDuty, Security Hub, and SIEM integration
- Image signing and verification with Cosign
- Registry allowlisting and image-digest enforcement
- Software Bill of Materials generation and provenance controls
- Kubernetes NetworkPolicies and namespace security controls
- Falco or an equivalent runtime detection layer
- Security Hub, Jira, Slack, or incident-management integrations
- Improved Prowler normalization, deduplication, asset ownership, and remediation tracking
- Time-series Grafana dashboards and alerting for security metrics

## Safe cleanup

AWS resources continue to incur charges until destroyed. After the demonstration, destroy both Terraform stacks and deactivate or delete the lab access key. The exact commands are included in `docs/SETUP.md`.

## Disclaimer

The insecure Terraform, Docker, and Kubernetes examples are deliberate test fixtures. Do not deploy them to a real environment.
