###############################################
# addons.tf - EKS Add-ons and IAM Roles
###############################################

# OIDC Provider for IRSA
resource "aws_iam_openid_connect_provider" "this" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

data "tls_certificate" "cluster" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

# VPC CNI Add-on
resource "aws_eks_addon" "vpc_cni" {
  count = var.enable_vpc_cni ? 1 : 0

  cluster_name                = aws_eks_cluster.this.name
  addon_name                 = "vpc-cni"
  addon_version              = var.addon_version_preferences.vpc_cni == "latest" ? data.aws_eks_addon_version.vpc_cni[0].version : var.addon_version_preferences.vpc_cni
  resolve_conflicts_on_create = var.addon_conflict_resolution.on_create
  resolve_conflicts_on_update = var.addon_conflict_resolution.on_update
  configuration_values       = jsonencode(var.addon_configurations.vpc_cni)
  service_account_role_arn   = aws_iam_role.aws_load_balancer_controller[0].arn

  timeouts {
    create = var.addon_timeouts.create
    update = var.addon_timeouts.update
    delete = var.addon_timeouts.delete
  }

  tags = merge(
    var.tags,
    var.addon_tags,
    {
      Name = "${var.cluster_name}-vpc-cni"
    }
  )

  depends_on = [
    aws_eks_node_group.this
  ]
}

# CoreDNS Add-on
resource "aws_eks_addon" "coredns" {
  count = var.enable_coredns ? 1 : 0

  cluster_name                = aws_eks_cluster.this.name
  addon_name                 = "coredns"
  addon_version              = var.addon_version_preferences.coredns == "latest" ? data.aws_eks_addon_version.coredns[0].version : var.addon_version_preferences.coredns
  resolve_conflicts_on_create = var.addon_conflict_resolution.on_create
  resolve_conflicts_on_update = var.addon_conflict_resolution.on_update
  configuration_values       = jsonencode(var.addon_configurations.coredns)

  timeouts {
    create = var.addon_timeouts.create
    update = var.addon_timeouts.update
    delete = var.addon_timeouts.delete
  }

  tags = merge(
    var.tags,
    var.addon_tags,
    {
      Name = "${var.cluster_name}-coredns"
    }
  )

  depends_on = [
    aws_eks_node_group.this
  ]
}

# Kube-proxy Add-on
resource "aws_eks_addon" "kube_proxy" {
  count = var.enable_kube_proxy ? 1 : 0

  cluster_name                = aws_eks_cluster.this.name
  addon_name                 = "kube-proxy"
  addon_version              = var.addon_version_preferences.kube_proxy == "latest" ? data.aws_eks_addon_version.kube_proxy[0].version : var.addon_version_preferences.kube_proxy
  resolve_conflicts_on_create = var.addon_conflict_resolution.on_create
  resolve_conflicts_on_update = var.addon_conflict_resolution.on_update
  configuration_values       = jsonencode(var.addon_configurations.kube_proxy)

  timeouts {
    create = var.addon_timeouts.create
    update = var.addon_timeouts.update
    delete = var.addon_timeouts.delete
  }

  tags = merge(
    var.tags,
    var.addon_tags,
    {
      Name = "${var.cluster_name}-kube-proxy"
    }
  )

  depends_on = [
    aws_eks_node_group.this
  ]
}

# EBS CSI Driver Add-on
resource "aws_eks_addon" "ebs_csi" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  cluster_name                = aws_eks_cluster.this.name
  addon_name                 = "aws-ebs-csi-driver"
  addon_version              = var.addon_version_preferences.ebs_csi == "latest" ? data.aws_eks_addon_version.ebs_csi[0].version : var.addon_version_preferences.ebs_csi
  resolve_conflicts_on_create = var.addon_conflict_resolution.on_create
  resolve_conflicts_on_update = var.addon_conflict_resolution.on_update
  configuration_values       = jsonencode(var.addon_configurations.ebs_csi)
  service_account_role_arn   = aws_iam_role.ebs_csi_driver[0].arn

  timeouts {
    create = var.addon_timeouts.create
    update = var.addon_timeouts.update
    delete = var.addon_timeouts.delete
  }

  tags = merge(
    var.tags,
    var.addon_tags,
    {
      Name = "${var.cluster_name}-ebs-csi-driver"
    }
  )

  depends_on = [
    aws_eks_node_group.this
  ]
}

# AWS Load Balancer Controller IAM Role
resource "aws_iam_role" "aws_load_balancer_controller" {
  count = var.enable_aws_load_balancer_controller ? 1 : 0

  name = "${var.cluster_name}-aws-load-balancer-controller"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.this.arn
        }
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.this.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-aws-load-balancer-controller"
    }
  )
}

# AWS Load Balancer Controller IAM Policy
resource "aws_iam_policy" "aws_load_balancer_controller" {
  count = var.enable_aws_load_balancer_controller ? 1 : 0

  name = "${var.cluster_name}-aws-load-balancer-controller"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateServiceLinkedRole",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "aws_load_balancer_controller" {
  count = var.enable_aws_load_balancer_controller ? 1 : 0

  role       = aws_iam_role.aws_load_balancer_controller[0].name
  policy_arn = aws_iam_policy.aws_load_balancer_controller[0].arn
}

# EBS CSI Driver IAM Role
resource "aws_iam_role" "ebs_csi_driver" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  name = "${var.cluster_name}-ebs-csi-driver"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.this.arn
        }
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.this.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-ebs-csi-driver"
    }
  )
}

# EBS CSI Driver IAM Policy
resource "aws_iam_policy" "ebs_csi_driver" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  name = "${var.cluster_name}-ebs-csi-driver"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:AttachVolume",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DescribeInstances",
          "ec2:DescribeSnapshots",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DetachVolume"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_driver" {
  count = var.enable_ebs_csi_driver ? 1 : 0

  role       = aws_iam_role.ebs_csi_driver[0].name
  policy_arn = aws_iam_policy.ebs_csi_driver[0].arn
} 