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
output "vpc_cni_addon" {
  description = "VPC CNI add-on details"
  value = var.enable_vpc_cni ? {
    arn     = aws_eks_addon.vpc_cni[0].arn
    version = aws_eks_addon.vpc_cni[0].addon_version
    status  = aws_eks_addon.vpc_cni[0].status
  } : null
}

output "coredns_addon" {
  description = "CoreDNS add-on details"
  value = var.enable_coredns ? {
    arn     = aws_eks_addon.coredns[0].arn
    version = aws_eks_addon.coredns[0].addon_version
    status  = aws_eks_addon.coredns[0].status
  } : null
}

output "kube_proxy_addon" {
  description = "kube-proxy add-on details"
  value = var.enable_kube_proxy ? {
    arn     = aws_eks_addon.kube_proxy[0].arn
    version = aws_eks_addon.kube_proxy[0].addon_version
    status  = aws_eks_addon.kube_proxy[0].status
  } : null
}

output "ebs_csi_addon" {
  description = "EBS CSI Driver add-on details"
  value = var.enable_ebs_csi_driver ? {
    arn     = aws_eks_addon.ebs_csi[0].arn
    version = aws_eks_addon.ebs_csi[0].addon_version
    status  = aws_eks_addon.ebs_csi[0].status
  } : null
}

output "addon_versions" {
  description = "Available add-on versions for the cluster"
  value = {
    vpc_cni   = var.enable_vpc_cni ? data.aws_eks_addon_version.vpc_cni[0].version : null
    coredns   = var.enable_coredns ? data.aws_eks_addon_version.coredns[0].version : null
    kube_proxy = var.enable_kube_proxy ? data.aws_eks_addon_version.kube_proxy[0].version : null
    ebs_csi   = var.enable_ebs_csi_driver ? data.aws_eks_addon_version.ebs_csi[0].version : null
  }
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

# Access Entries Outputs
output "access_entries" {
  description = "Map of all configured access entries"
  value = {
    for key, entry in aws_eks_access_entry.this : key => {
      principal_arn     = entry.principal_arn
      kubernetes_groups = entry.kubernetes_groups
      type             = entry.type
      status           = entry.status
    }
  }
}

output "access_policy_associations" {
  description = "Map of all policy associations"
  value = {
    for key, assoc in aws_eks_access_policy_association.this : key => {
      principal_arn = assoc.principal_arn
      policy_arn    = assoc.policy_arn
      access_scope  = assoc.access_scope
    }
  }
}

output "admin_access_entries" {
  description = "Access entries with cluster-wide admin permissions"
  value = {
    for key, assoc in aws_eks_access_policy_association.this : 
      key => assoc if assoc.access_scope[0].type == "cluster" && 
        contains(["arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"], assoc.policy_arn)
  }
}

output "namespace_access_entries" {
  description = "Access entries with namespace-scoped permissions"
  value = {
    for key, assoc in aws_eks_access_policy_association.this : 
      key => assoc if assoc.access_scope[0].type == "namespace"
  }
} 