# Single-node K3s cluster on EC2. Hosts the GrokGuard admission demo.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "admin_cidr" {
  description = "CIDR allowed to reach SSH and the K8s API, e.g. x.x.x.x/32"
  type        = string
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key for the node"
  type        = string
  default     = "~/.ssh/aegis_k3s.pub"
}

data "aws_vpc" "default" {
  default = true
}

# current Ubuntu 22.04 AMI via SSM
data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

resource "aws_key_pair" "k3s" {
  key_name   = "aegis-k3s-key"
  public_key = file(var.ssh_public_key_path)
}

# static IP allocated first so the K3s TLS cert can include it
resource "aws_eip" "k3s" {
  domain = "vpc"

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

resource "aws_security_group" "k3s" {
  name        = "aegis-k3s-sg"
  description = "K3s node, SSH and API restricted to admin CIDR"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH, admin only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  ingress {
    description = "Kubernetes API, admin only"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

resource "aws_instance" "k3s" {
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = "t3.small"
  key_name               = aws_key_pair.k3s.key_name
  vpc_security_group_ids = [aws_security_group.k3s.id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }

  user_data = <<-EOT
    #!/bin/bash
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--tls-san ${aws_eip.k3s.public_ip} --write-kubeconfig-mode 644" sh -
  EOT

  tags = {
    Name    = "aegis-k3s-node"
    Project = "aegispipeline"
    Env     = "demo"
  }
}

resource "aws_eip_association" "k3s" {
  instance_id   = aws_instance.k3s.id
  allocation_id = aws_eip.k3s.id
}

output "cluster_public_ip" {
  value = aws_eip.k3s.public_ip
}

output "ssh_command" {
  value = "ssh -i ~/.ssh/aegis_k3s ubuntu@${aws_eip.k3s.public_ip}"
}

output "fetch_kubeconfig" {
  value = "scp -i ~/.ssh/aegis_k3s ubuntu@${aws_eip.k3s.public_ip}:/etc/rancher/k3s/k3s.yaml ./kubeconfig && sed -i 's/127.0.0.1/${aws_eip.k3s.public_ip}/' ./kubeconfig"
}
