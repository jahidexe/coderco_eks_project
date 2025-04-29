# Reference to current account for conditions
data "aws_caller_identity" "current" {}

# KMS key for EKS cluster encryption
resource "aws_kms_key" "cluster" {
  description             = "KMS key for EKS cluster ${var.cluster_name} encryption"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true
  tags                    = local.resource_tags["kms_key"]
}

resource "aws_kms_alias" "cluster" {
  name          = "alias/${local.names.kms_key}"
  target_key_id = aws_kms_key.cluster.key_id
}

# EKS Cluster
resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = local.features.private_access
    endpoint_public_access  = local.features.public_access
    security_group_ids      = var.create_cluster_security_group ? [aws_security_group.cluster[0].id] : []
  }

  kubernetes_network_config {
    service_ipv4_cidr = var.service_ipv4_cidr
    ip_family         = var.ip_family
  }

  enabled_cluster_log_types = local.features.logging_enabled ? var.enabled_cluster_log_types : []

  encryption_config {
    provider {
      key_arn = aws_kms_key.cluster.arn
    }
    resources = ["secrets"]
  }

  tags = local.common_tags

  # Ensure IAM role permissions are created before cluster
  depends_on = [
    aws_iam_role_policy_attachment.cluster_policies,
    aws_cloudwatch_log_group.eks_logs
  ]

  lifecycle {
    # Prevent accidental cluster replacement
    prevent_destroy = false
  }
}

# CloudWatch Log Group for EKS control plane logs
resource "aws_cloudwatch_log_group" "eks_logs" {
  count             = length(var.enabled_cluster_log_types) > 0 ? 1 : 0
  name              = local.names.log_group
  retention_in_days = var.log_retention_days
  tags              = local.resource_tags["log_group"]
}

# Access Entries
resource "aws_eks_access_entry" "this" {
  for_each = var.access_entries

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  type          = each.value.type

  kubernetes_groups = each.value.kubernetes_groups

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-access-entry-${each.key}"
    }
  )
}

# Policy Associations
resource "aws_eks_access_policy_association" "this" {
  for_each = merge([
    for entry_key, entry in var.access_entries : {
      for assoc_key, assoc in entry.policy_associations :
      "${entry_key}-${assoc_key}" => {
        entry_key = entry_key
        assoc     = assoc
      }
    }
  ]...)

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_eks_access_entry.this[each.value.entry_key].principal_arn
  policy_arn    = each.value.assoc.policy_arn

  access_scope {
    type       = each.value.assoc.access_scope.type
    namespaces = each.value.assoc.access_scope.type == "namespace" ? each.value.assoc.access_scope.namespaces : null
  }

  depends_on = [
    aws_eks_access_entry.this
  ]
}

# Add-on Version Data Sources
data "aws_eks_addon_version" "addons" {
  for_each = { for k, v in local.addons : k => v if v.enabled }

  addon_name         = each.value.name
  kubernetes_version = aws_eks_cluster.this.version
  most_recent        = var.addon_version_preferences[each.key] == "latest"
}

# Add-ons
resource "aws_eks_addon" "addons" {
  for_each = { for k, v in local.addons : k => v if v.enabled }

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.value.name
  addon_version               = data.aws_eks_addon_version.addons[each.key].version
  resolve_conflicts_on_create = var.addon_conflict_resolution.on_create
  resolve_conflicts_on_update = var.addon_conflict_resolution.on_update

  # Special handling for EBS CSI driver
  service_account_role_arn = each.key == "ebs_csi" ? aws_iam_role.ebs_csi_driver[0].arn : null

  tags = merge(
    local.common_tags,
    var.addon_tags,
    {
      Name = "${var.cluster_name}-${each.key}"
    }
  )

  depends_on = [
    aws_eks_node_group.this
  ]
}

# VPC Endpoints
resource "aws_vpc_endpoint" "endpoints" {
  for_each = local.vpc_endpoints

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.${each.value.service}"
  vpc_endpoint_type   = each.value.type
  security_group_ids  = [aws_security_group.cluster[0].id]
  subnet_ids          = var.subnet_ids
  private_dns_enabled = true

  tags = merge(
    local.common_tags,
    {
      Name = "${var.cluster_name}-${each.key}-endpoint"
    }
  )
}

