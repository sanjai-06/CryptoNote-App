output "ecr_server_url" {
  description = "ECR URL for the backend server image"
  value       = aws_ecr_repository.server.repository_url
}

output "ecr_frontend_url" {
  description = "ECR URL for the frontend image"
  value       = aws_ecr_repository.frontend.repository_url
}

output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.cryptonote.name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = aws_eks_cluster.cryptonote.endpoint
}

output "eks_kubeconfig_command" {
  description = "Command to configure kubectl for this cluster"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${var.cluster_name}"
}
