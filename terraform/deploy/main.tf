# Intentionally misconfigured. Test fixtures for the CI gate. Do not deploy.

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

# no encryption, no versioning
resource "aws_s3_bucket" "model_artifacts" {
  bucket = "aegis-demo-model-artifacts-insecure"

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

# public access left open
resource "aws_s3_bucket_public_access_block" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ssh open to 0.0.0.0/0
resource "aws_security_group" "training_nodes" {
  name        = "aegis-demo-training-sg-insecure"
  description = "Security group for training nodes"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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

# wildcard action + wildcard resource
resource "aws_iam_policy" "researcher_access" {
  name        = "aegis-demo-researcher-policy-insecure"
  description = "Access policy for research team"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
