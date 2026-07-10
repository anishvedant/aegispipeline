# AegisPipeline

A multi-cloud DevSecOps security gate. You push Terraform, it gets scanned for misconfigurations, hardcoded secrets, and vulnerable container images before anything ships. If something high or critical shows up, the build fails and the change is blocked. After deploy, the live cloud account gets a posture scan too. All the findings land in one report, and an AI layer re-ranks them by real blast radius instead of generic scanner severity.

I built this because most cloud breaches are not clever zero days. They are a public S3 bucket, an IAM role with a wildcard, an SSH port open to the whole internet, stuff that should have been caught in review and was not. People miss these when they are tired or moving fast. Machines do not. So the review here is a machine and it runs on every single push.

The multi-cloud part is deliberate. I did not want a tool that only knows AWS, so the same idea is wired for both AWS and Azure, with a broken and a hardened version of each resource sitting side by side so you can see exactly what the gate catches and exactly how it gets fixed.

## How it works

```
 push
  |
  v
+---------------------------------------------------+
|  GitHub Actions security gate                     |
|                                                   |
|  Checkov ---- IaC policy scan + custom rules      |
|  Trivy ------ IaC second opinion + image CVEs     |
|  Gitleaks --- secrets across full git history     |
|                                                   |
|  any HIGH or CRITICAL  ->  build fails, blocked   |
+---------------------------------------------------+
  |
  v  only clean infra gets past here
 terraform apply
  |
  v
 Prowler live posture scan (CSPM)
  |
  v
 aggregate.py  ->  one normalized report, compliance tagged
  |
  v
 ai_triage.py  ->  findings ranked by real risk + drafted fixes
```

## Layout

- `terraform/aws/` and `terraform/azure/` each hold an `insecure/` and a `secure/` copy of the same resources. Insecure ones exist to get caught. Secure ones are the fix.
- `terraform/deploy/` is the staging area the gate scans, and the only place I ever run `terraform apply`.
- `.github/workflows/security.yml` is the gate. Five jobs, fails closed.
- `policies/` holds a custom Checkov rule, because running someone else's scanner is easy and writing your own policy is the actual skill.
- `scripts/aggregate.py` takes every scanner's output, which are all in different JSON shapes, and normalizes them into one findings format tagged with CIS, PCI DSS, HIPAA and GDPR references.
- `scripts/ai_triage.py` sends the findings to Grok for blast-radius ranking and drafted remediations, with a local fallback so it still works with no API key.
- `docs/SETUP_GUIDE.md` walks the whole thing from a clean machine.

## Quick start

Scan the deliberately broken infra and watch it fail:

    cp terraform/aws/insecure/main.tf terraform/deploy/main.tf && checkov -d terraform/deploy --external-checks-dir policies --compact

Swap in the hardened version and watch it pass:

    cp terraform/aws/secure/main.tf terraform/deploy/main.tf && checkov -d terraform/deploy --external-checks-dir policies --compact

Full walkthrough, including the live cloud posture scan, is in `docs/SETUP_GUIDE.md`.

## A few design choices

Two IaC scanners instead of one, because different engines have different blind spots and anything both of them flag is almost certainly real. The gate only fails on high and critical so it stays trusted instead of turning into noise nobody reads. Gitleaks looks at the entire git history, not just the latest commit, because deleting a secret from a file does not remove it from history, so the real fix is always rotating the key. And the AI layer has an offline fallback on purpose, since a security control that dies when an external API is down is not much of a control.

## What this is not

This is a lab build, not a production rollout. Production would add remote encrypted Terraform state, OIDC federated pipeline credentials instead of static keys, a real secrets manager, and org-wide policy enforcement. The structure is all here. The hardening around it is the next step.

## GrokGuard: the Kubernetes admission layer

The CI gate stops bad infrastructure code, but workloads can reach a cluster by other paths, a manual kubectl apply, a compromised CI token, an unreviewed hotfix. GrokGuard is the backstop: Kyverno admission policies (`k8s/policies/`) that reject non-compliant pods at the moment they try to enter the cluster, no matter how they got there.

The policies enforce the controls that matter most on AI training infrastructure: no hostPath mounts (the shortest path to reading model checkpoints off a GPU node), no privileged containers, non-root execution, pinned image tags, and mandatory resource limits so one runaway pod cannot starve a shared node. `k8s/workloads/` ships an intentionally broken deployment that violates all five and a hardened twin that passes clean, the same red-to-green pattern as the Terraform side.

`monitoring/` turns aggregated findings into Prometheus metrics via a small exporter, so security posture can live on the same Grafana dashboard as CPU and latency instead of dying in a JSON file.

## Cloud cluster

`terraform/aws/k3s-cluster/` provisions a single-node K3s cluster (certified lightweight Kubernetes) on EC2: static IP, SSH and API locked to an admin CIDR, encrypted root volume, IMDSv2 enforced. The GrokGuard admission policies apply to it unchanged, and they would apply to EKS unchanged too, which is the point of policy-as-code. `docker/` holds the triage API the pipeline builds and scans, a small FastAPI service that severity-ranks findings.
