###############################################
# iam.tf - EKS Cluster IAM Resources
###############################################

# EKS Cluster IAM Role
resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-cluster-role"
    }
  )
}

# Dynamic IAM policy attachments
resource "aws_iam_role_policy_attachment" "cluster_policies" {
  for_each   = toset(var.cluster_policies)
  policy_arn = each.value
  role       = aws_iam_role.cluster.name
}

# Consolidated OIDC Provider for IRSA
resource "aws_iam_openid_connect_provider" "eks_oidc" {
  count = var.enable_irsa ? 1 : 0

  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]

  tags = merge(
    var.tags,
    {
      Name                                        = "${var.cluster_name}-oidc-provider"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    }
  )
}

# TLS Certificate for OIDC
data "tls_certificate" "eks" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

# IRSA Helper Locals
locals {
  oidc_provider_arn = var.enable_irsa ? aws_iam_openid_connect_provider.eks_oidc[0].arn : ""
  oidc_provider_url = var.enable_irsa ? replace(aws_iam_openid_connect_provider.eks_oidc[0].url, "https://", "") : ""
}

# Example IAM Role for Service Account with improved configuration
resource "aws_iam_role" "service_account_role" {
  name = "${var.cluster_name}-service-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = local.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${local.oidc_provider_url}:sub" = "system:serviceaccount:default:service-account-name"
            "${local.oidc_provider_url}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name                                        = "${var.cluster_name}-service-account-role"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    }
  )

  depends_on = [aws_iam_openid_connect_provider.eks_oidc]
}

# IAM Role for AWS Load Balancer Controller with improved OIDC configuration
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
          Federated = local.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${local.oidc_provider_url}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
            "${local.oidc_provider_url}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name                                        = "${var.cluster_name}-aws-load-balancer-controller"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    }
  )

  depends_on = [aws_iam_openid_connect_provider.eks_oidc]
}

# IAM Role for EBS CSI Driver with improved OIDC configuration
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
          Federated = local.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${local.oidc_provider_url}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
            "${local.oidc_provider_url}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name                                        = "${var.cluster_name}-ebs-csi-driver"
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    }
  )

  depends_on = [aws_iam_openid_connect_provider.eks_oidc]
}

# Custom IAM policy for node groups
resource "aws_iam_policy" "node_group" {
  for_each = var.managed_node_groups

  name        = "${var.cluster_name}-${each.key}-node-group-policy"
  description = "Custom policy for EKS node group with least privilege"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EC2 instance management
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:AttachVolume",
          "ec2:DetachVolume",
          "ec2:DescribeVolumeStatus",
          "ec2:DescribeVolumesModifications",
          "ec2:ModifyVolume",
          "ec2:DescribeInstanceTypes",

          # Load balancing
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",

          # ACM certificates
          "acm:DescribeCertificate",
          "acm:ListCertificates",

          # Autoscaling
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeTags",

          # IAM for service accounts
          "iam:GetRole",
          "iam:ListAttachedRolePolicies",

          # CloudWatch logging
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",

          # Secret access for pulling private images
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",

          # KMS for volume encryption/decryption
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKeyWithoutPlaintext"
        ],
        Resource = "*"
      },
      {
        # S3 access with more limited scope for specific buckets
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        Resource = [
          "arn:aws:s3:::${var.cluster_name}-*",
          "arn:aws:s3:::${var.cluster_name}-*/*",
          "arn:aws:s3:::eks-*",
          "arn:aws:s3:::eks-*/*"
        ]
      },
      {
        # STS permissions for AssumeRole
        Effect = "Allow",
        Action = [
          "sts:AssumeRole",
          "sts:GetServiceBearerToken"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "aws:ResourceAccount" : "${data.aws_caller_identity.current.account_id}"
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    }
  )
}

# Attach policy to node group roles
resource "aws_iam_role_policy_attachment" "node_group" {
  for_each = var.managed_node_groups

  policy_arn = aws_iam_policy.node_group[each.key].arn
  role       = aws_iam_role.node_group[each.key].name
}
