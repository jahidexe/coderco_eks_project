###############################################
# outputs.tf - EKS Cluster Module Outputs
###############################################

# EKS Cluster Outputs
output "cluster_id" {
  description = "The name of the EKS cluster"
  value       = aws_eks_cluster.this.id
}

output "cluster_arn" {
  description = "The Amazon Resource Name (ARN) of the cluster"
  value       = aws_eks_cluster.this.arn
}

output "cluster_endpoint" {
  description = "The endpoint for the EKS Kubernetes API"
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = aws_security_group.cluster.id
}

output "cluster_iam_role_name" {
  description = "IAM role name of the EKS cluster"
  value       = aws_iam_role.cluster.name
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN of the EKS cluster"
  value       = aws_iam_role.cluster.arn
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster OIDC Issuer"
  value       = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

output "cluster_oidc_provider_arn" {
  description = "The ARN of the OIDC Provider if `enable_irsa = true`"
  value       = var.enable_irsa ? aws_iam_openid_connect_provider.this.arn : null
}

output "cluster_version" {
  description = "The Kubernetes version for the EKS cluster"
  value       = aws_eks_cluster.this.version
}

output "cluster_platform_version" {
  description = "Platform version for the EKS cluster"
  value       = aws_eks_cluster.this.platform_version
}

output "cluster_status" {
  description = "Status of the EKS cluster"
  value       = aws_eks_cluster.this.status
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encrypting EKS secrets"
  value       = aws_kms_key.cluster.arn
}

# Node Group Outputs
output "node_groups" {
  description = "Map of node group attributes"
  value       = aws_eks_node_group.this
}

output "node_group_arns" {
  description = "ARNs of the EKS node groups"
  value       = { for k, v in aws_eks_node_group.this : k => v.arn }
}

output "node_group_ids" {
  description = "IDs of the EKS node groups"
  value       = { for k, v in aws_eks_node_group.this : k => v.id }
}

output "node_group_role_arns" {
  description = "ARNs of the EKS node group IAM roles"
  value       = { for k, v in aws_iam_role.node_group : k => v.arn }
}

# Fargate Outputs
output "fargate_profile_arns" {
  description = "ARNs of the EKS Fargate profiles"
  value       = { for k, v in aws_eks_fargate_profile.this : k => v.arn }
}

output "fargate_profile_ids" {
  description = "IDs of the EKS Fargate profiles"
  value       = { for k, v in aws_eks_fargate_profile.this : k => v.id }
}

output "fargate_role_arns" {
  description = "ARNs of the EKS Fargate IAM roles"
  value       = { for k, v in aws_iam_role.fargate : k => v.arn }
}

# Add-ons Outputs
output "vpc_cni_addon_arn" {
  description = "ARN of the VPC CNI add-on"
  value       = var.enable_vpc_cni ? aws_eks_addon.vpc_cni[0].arn : null
}

output "coredns_addon_arn" {
  description = "ARN of the CoreDNS add-on"
  value       = var.enable_coredns ? aws_eks_addon.coredns[0].arn : null
}

output "kube_proxy_addon_arn" {
  description = "ARN of the kube-proxy add-on"
  value       = var.enable_kube_proxy ? aws_eks_addon.kube_proxy[0].arn : null
}

output "aws_load_balancer_controller_role_arn" {
  description = "ARN of the AWS Load Balancer Controller IAM role"
  value       = var.enable_aws_load_balancer_controller ? aws_iam_role.aws_load_balancer_controller[0].arn : null
}

output "ebs_csi_driver_role_arn" {
  description = "ARN of the EBS CSI Driver IAM role"
  value       = var.enable_ebs_csi_driver ? aws_iam_role.ebs_csi_driver[0].arn : null
}

# Security Outputs
output "node_security_group_id" {
  description = "ID of the node shared security group"
  value       = aws_security_group.node.id
}

output "node_security_group_arn" {
  description = "ARN of the node security group"
  value       = aws_security_group.node.arn
}

output "cluster_encryption_config" {
  description = "Cluster encryption configuration"
  value       = aws_eks_cluster.this.encryption_config
}

# Observability Outputs
output "container_insights_log_group_name" {
  description = "Name of the Container Insights CloudWatch log group"
  value       = var.enable_container_insights ? aws_cloudwatch_log_group.container_insights[0].name : null
}

output "cloudwatch_agent_role_arn" {
  description = "ARN of the CloudWatch agent IAM role"
  value       = var.enable_cloudwatch_metrics ? aws_iam_role.cloudwatch_agent[0].arn : null
}

# Kubeconfig Output
output "kubeconfig" {
  description = "kubectl config file contents for this EKS cluster"
  value = templatefile("${path.module}/templates/kubeconfig.tpl", {
    cluster_name     = aws_eks_cluster.this.name
    endpoint         = aws_eks_cluster.this.endpoint
    certificate_data = aws_eks_cluster.this.certificate_authority[0].data
    region           = var.region
  })
  sensitive = true
} 