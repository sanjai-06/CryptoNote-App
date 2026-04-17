terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── ECR Repository: backend server ───────────────────────────────────────────
resource "aws_ecr_repository" "server" {
  name                 = "cryptonote-server"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = "CryptoNote"
    Environment = "production"
  }
}

# ── ECR Repository: frontend ──────────────────────────────────────────────────
resource "aws_ecr_repository" "frontend" {
  name                 = "cryptonote-frontend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = "CryptoNote"
    Environment = "production"
  }
}

# ── ECR Lifecycle Policy: keep last 10 images ─────────────────────────────────
resource "aws_ecr_lifecycle_policy" "server_policy" {
  repository = aws_ecr_repository.server.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "frontend_policy" {
  repository = aws_ecr_repository.frontend.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 10 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# ── VPC (use default VPC to minimize cost) ────────────────────────────────────
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}
