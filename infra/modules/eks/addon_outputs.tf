###############################################
# addon_outputs.tf - EKS Add-on Outputs
###############################################

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