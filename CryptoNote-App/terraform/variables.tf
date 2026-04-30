variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-north-1"
}

variable "aws_account_id" {
  description = "AWS Account ID (12-digit)"
  type        = string
  default     = "997416683939"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "cryptonote-cluster"
}

variable "node_instance_type" {
  description = "EC2 instance type for EKS worker nodes"
  type        = string
  default     = "t3.medium"
}

variable "node_desired_count" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 1
}

variable "node_min_count" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 1
}

variable "node_max_count" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 2
}
