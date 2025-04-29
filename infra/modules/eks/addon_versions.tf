###############################################
# addon_versions.tf - EKS Add-on Version Data Sources
###############################################

# Data source to get available add-on versions
data "aws_eks_addon_version" "vpc_cni" {
  count = var.enable_vpc_cni ? 1 : 0

  addon_name         = "vpc-cni"
  kubernetes_version = aws_eks_cluster.this.version
  most_recent        = var.addon_version_preferences.vpc_cni == "latest" ? true : false
}

data "aws_eks_addon_version" "coredns" {
  count = var.enable_coredns ? 1 : 0

  addon_name         = "coredns"
  kubernetes_version = aws_eks_cluster.this.version
  most_recent        = var.addon_version_preferences.coredns == "latest" ? true : false
}

data "aws_eks_addon_version" "kube_proxy" {
  count = var.enable_kube_proxy ? 1 : 0

  addon_name         = "kube-proxy"
  kubernetes_version = aws_eks_cluster.this.version
  most_recent        = var.addon_version_preferences.kube_proxy == "latest" ? true : false
}

data "aws_eks_addon_version" "ebs_csi" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  addon_name         = "aws-ebs-csi-driver"
  kubernetes_version = aws_eks_cluster.this.version
  most_recent        = var.addon_version_preferences.ebs_csi == "latest" ? true : false
}

# Data source to get add-on configuration schema
data "aws_eks_addon_configuration" "vpc_cni" {
  count = var.enable_vpc_cni ? 1 : 0

  addon_name         = "vpc-cni"
  kubernetes_version = aws_eks_cluster.this.version
}

data "aws_eks_addon_configuration" "coredns" {
  count = var.enable_coredns ? 1 : 0

  addon_name         = "coredns"
  kubernetes_version = aws_eks_cluster.this.version
}

data "aws_eks_addon_configuration" "kube_proxy" {
  count = var.enable_kube_proxy ? 1 : 0

  addon_name         = "kube-proxy"
  kubernetes_version = aws_eks_cluster.this.version
}

data "aws_eks_addon_configuration" "ebs_csi" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  addon_name         = "aws-ebs-csi-driver"
  kubernetes_version = aws_eks_cluster.this.version
} 