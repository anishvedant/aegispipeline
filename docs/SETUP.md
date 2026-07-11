# AegisPipeline Setup and Demonstration Guide

This guide reproduces the completed AWS and Kubernetes lab from a clean workstation. Run commands from the repository root unless a section changes directories.

## 1. Safety rules

- Never commit or paste AWS secret keys, xAI API keys, private SSH keys, kubeconfig files, Terraform state, Terraform plans, VPN profiles, or `.env` files.
- Deploy only `terraform/deploy/`, never `terraform/aws/insecure/` or `terraform/azure/insecure/`.
- Restrict SSH and Kubernetes API access to your current public `/32` CIDR.
- Set an AWS Budget alert before creating EC2 resources.
- Destroy the AWS resources and delete the lab access key after the demonstration.

## 2. Required tools

Required for the complete run:

- Git
- Python 3.12 or compatible Python 3
- Terraform
- AWS CLI v2
- Checkov
- Trivy
- Gitleaks
- Prowler
- kubectl

Optional:

- Docker and Docker Compose, for the image and monitoring demonstrations
- An xAI API key, for Grok-backed triage instead of the offline heuristic

Verify the tools:

```bash
terraform version
aws --version
checkov --version
trivy --version
gitleaks version
prowler -v
kubectl version --client
python3 --version
```

## 3. Repository location

The commands below assume:

```bash
cd ~/Desktop/projects/aegispipeline
```

## 4. Configure AWS access

For this lab, configure a dedicated AWS identity and verify it before deploying:

```bash
aws configure
aws sts get-caller-identity
```

Do not paste the access key ID or secret access key into chat, source code, shell scripts, or Git.

For production, replace long-lived access keys with federation and short-lived role credentials.

## 5. Compare the insecure and secure Terraform fixtures

Scan the deliberately insecure AWS fixture:

```bash
cp terraform/aws/insecure/main.tf terraform/deploy/main.tf
checkov -d terraform/deploy --framework terraform --external-checks-dir policies --compact || true
trivy config terraform/deploy
```

Restore the hardened staging configuration:

```bash
cp terraform/aws/secure/main.tf terraform/deploy/main.tf
terraform fmt terraform/deploy/main.tf
checkov -d terraform/deploy --framework terraform --external-checks-dir policies --compact || true
trivy config terraform/deploy
```

Do not run `terraform apply` while the insecure fixture is staged.

## 6. Generate local scanner outputs

```bash
mkdir -p reports

checkov \
  -d terraform/deploy \
  --framework terraform \
  --external-checks-dir policies \
  -o json > reports/checkov.json || true

trivy config terraform/deploy \
  --format json \
  --output reports/trivy-config.json

gitleaks detect \
  --source . \
  --report-format json \
  --report-path reports/gitleaks.json \
  --exit-code 0
```

A Gitleaks result must be investigated even when the demonstration command uses `--exit-code 0` to preserve the report. Any real credential found in current or historical Git content must be revoked or rotated.

## 7. Deploy the hardened AWS baseline

```bash
MYIP="$(curl -s ifconfig.me)"
ADMIN_CIDR="${MYIP}/32"

cd ~/Desktop/projects/aegispipeline/terraform/deploy

terraform init
terraform validate
terraform plan \
  -var "admin_cidr=${ADMIN_CIDR}" \
  -out=aegis-phase5.tfplan
terraform apply "aegis-phase5.tfplan"
terraform output
```

This stack creates the model-artifact S3 bucket, public-access block, AES-256 server-side encryption, versioning, a restricted security group, and a least-privilege S3 read policy.

The Terraform plan file is local evidence only and must not be committed.

## 8. Run the live AWS posture scan

Return to the repository root:

```bash
cd ~/Desktop/projects/aegispipeline
mkdir -p reports

prowler aws \
  --output-formats json-ocsf \
  --output-directory reports/
```

Prowler scans the complete AWS account. The result is not limited to AegisPipeline resources.

## 9. Aggregate and prioritize findings

```bash
cd ~/Desktop/projects/aegispipeline
python3 scripts/aggregate.py
python3 scripts/ai_triage.py
```

Expected outputs:

```text
reports/summary.json
reports/SUMMARY.md
reports/AI_REPORT.md
```

### Optional Grok mode

Set the xAI API key only in the current shell or a secret manager:

```bash
export XAI_API_KEY='YOUR_KEY_HERE'
python3 scripts/ai_triage.py
unset XAI_API_KEY
```

Never write the key into the repository. Without the variable, the script automatically uses local heuristic mode.

## 10. Create the K3s SSH key

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [ ! -f ~/.ssh/aegis_k3s ]; then
  ssh-keygen -t ed25519 -f ~/.ssh/aegis_k3s -N ""
fi

chmod 600 ~/.ssh/aegis_k3s
chmod 644 ~/.ssh/aegis_k3s.pub
```

## 11. Deploy the K3s cluster on AWS

```bash
MYIP="$(curl -s ifconfig.me)"
ADMIN_CIDR="${MYIP}/32"

cd ~/Desktop/projects/aegispipeline/terraform/aws/k3s-cluster

terraform init
terraform validate
terraform plan \
  -var "admin_cidr=${ADMIN_CIDR}" \
  -var "ssh_public_key_path=${HOME}/.ssh/aegis_k3s.pub" \
  -out=aegis-k3s.tfplan
terraform apply "aegis-k3s.tfplan"
terraform output
```

The stack creates an EC2 K3s node, Elastic IP, restricted security group, AWS key pair, encrypted GP3 root disk, and IMDSv2 enforcement.

## 12. Fetch kubeconfig and connect

```bash
cd ~/Desktop/projects/aegispipeline/terraform/aws/k3s-cluster

CLUSTER_IP="$(terraform output -raw cluster_public_ip)"

echo "Waiting for K3s at ${CLUSTER_IP}..."
until ssh \
  -o StrictHostKeyChecking=accept-new \
  -i ~/.ssh/aegis_k3s \
  ubuntu@"${CLUSTER_IP}" \
  "sudo test -f /etc/rancher/k3s/k3s.yaml"
do
  sleep 15
done

ssh \
  -o StrictHostKeyChecking=accept-new \
  -i ~/.ssh/aegis_k3s \
  ubuntu@"${CLUSTER_IP}" \
  "sudo cat /etc/rancher/k3s/k3s.yaml" > kubeconfig

sed -i "s/127.0.0.1/${CLUSTER_IP}/g" kubeconfig
chmod 600 kubeconfig

export KUBECONFIG="$PWD/kubeconfig"
kubectl get nodes -o wide
```

The kubeconfig contains cluster credentials and must not be committed.

## 13. Install Kyverno

```bash
export KUBECONFIG=~/Desktop/projects/aegispipeline/terraform/aws/k3s-cluster/kubeconfig

kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.18.0/install.yaml

kubectl wait \
  --namespace kyverno \
  --for=condition=Ready \
  pod \
  --all \
  --timeout=300s

kubectl -n kyverno get pods
```

## 14. Apply GrokGuard policies

```bash
cd ~/Desktop/projects/aegispipeline
export KUBECONFIG=~/Desktop/projects/aegispipeline/terraform/aws/k3s-cluster/kubeconfig

kubectl apply -f k8s/policies/grokguard-policies.yaml
kubectl get clusterpolicy
```

Expected policies:

```text
gg-block-hostpath
gg-pod-hardening
gg-supply-chain-and-limits
```

## 15. Test denial and admission

Create the namespace:

```bash
kubectl create namespace model-serving --dry-run=client -o yaml | kubectl apply -f -
```

Attempt the insecure workload and save the expected denial:

```bash
mkdir -p reports/k8s
kubectl apply -f k8s/workloads/insecure/grok-inference.yaml \
  2>&1 | tee reports/k8s/insecure-workload-blocked.txt || true
```

Apply the hardened workload:

```bash
kubectl delete deployment grok-inference -n model-serving --ignore-not-found=true
kubectl apply -f k8s/workloads/secure/grok-inference.yaml
kubectl -n model-serving rollout status deployment/grok-inference --timeout=300s
kubectl -n model-serving get deployments,pods -o wide
```

## 16. Save Kubernetes evidence

```bash
mkdir -p reports/k8s

kubectl get nodes -o wide > reports/k8s/nodes.txt
kubectl get clusterpolicy > reports/k8s/clusterpolicies.txt
kubectl -n kyverno get pods -o wide > reports/k8s/kyverno-pods.txt
kubectl -n model-serving get deployments,pods -o wide > reports/k8s/model-serving.txt
kubectl -n model-serving get events --sort-by=.lastTimestamp > reports/k8s/events.txt
```

## 17. Optional monitoring stack

Install the Prometheus Python client if needed:

```bash
python3 -m pip install prometheus-client
```

Start the exporter in one terminal:

```bash
cd ~/Desktop/projects/aegispipeline
python3 monitoring/security_exporter.py
```

The metrics endpoint is:

```text
http://localhost:9105/metrics
```

Start Prometheus and Grafana in another terminal:

```bash
cd ~/Desktop/projects/aegispipeline/monitoring
docker compose up -d
```

The monitoring folder is optional and is not required for the core AWS and Kubernetes demonstration.

## 18. Commit safe evidence and code

Review before staging:

```bash
cd ~/Desktop/projects/aegispipeline
git status
git diff
```

Never add Terraform state, Terraform plans, kubeconfig, private keys, `.env` files, VPN profiles, or cloud credentials.

Safe example:

```bash
git add \
  .github/workflows/security.yml \
  .github/workflows/security-k8s.yml \
  .gitignore \
  README.md \
  docs/SETUP.md \
  terraform/aws/secure/main.tf \
  terraform/deploy/main.tf \
  reports/k8s

git commit -m "Fix security workflows and document live architecture"
git push
```

## 19. Verify GitHub Actions

After pushing, open the repository Actions tab and confirm the latest `security-gate` run is green.

The workflow behavior is:

- Checkov blocks unaccepted high or critical Terraform findings.
- Gitleaks blocks secrets found in Git history.
- Trivy uploads IaC and image reports as non-blocking lab visibility.
- Kubernetes CI scans are non-blocking visibility, while live Kyverno admission is the authoritative enforcement control.

## 20. Destroy AWS resources after the demonstration

Destroy the K3s cluster:

```bash
MYIP="$(curl -s ifconfig.me)"
ADMIN_CIDR="${MYIP}/32"

cd ~/Desktop/projects/aegispipeline/terraform/aws/k3s-cluster

terraform destroy \
  -var "admin_cidr=${ADMIN_CIDR}" \
  -var "ssh_public_key_path=${HOME}/.ssh/aegis_k3s.pub"
```

Destroy the Phase 5 AWS resources:

```bash
MYIP="$(curl -s ifconfig.me)"
ADMIN_CIDR="${MYIP}/32"

cd ~/Desktop/projects/aegispipeline/terraform/deploy
terraform destroy -var "admin_cidr=${ADMIN_CIDR}"
```

Then deactivate and delete the lab IAM access key. Confirm that no EC2 instances, Elastic IPs, or unintended S3 resources remain.
