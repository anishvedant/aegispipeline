# Hardened baseline. Safe to deploy on free tier.

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

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "model_artifacts" {
  bucket = "aegis-demo-model-artifacts-${random_id.suffix.hex}"

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

variable "admin_cidr" {
  description = "CIDR allowed to reach SSH, e.g. x.x.x.x/32"
  type        = string
  default     = "203.0.113.10/32"
}

resource "aws_security_group" "training_nodes" {
  name        = "aegis-demo-training-sg"
  description = "Training nodes, SSH restricted to admin CIDR"

  ingress {
    description = "SSH, admin only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "Outbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }
}

# least privilege: read-only, scoped to one bucket
resource "aws_iam_policy" "researcher_access" {
  name        = "aegis-demo-researcher-policy"
  description = "Read access to the model artifacts bucket"

  tags = {
    Project = "aegispipeline"
    Env     = "demo"
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.model_artifacts.arn,
          "${aws_s3_bucket.model_artifacts.arn}/*"
        ]
      }
    ]
  })
}
