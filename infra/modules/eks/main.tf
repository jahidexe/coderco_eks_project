###############################################
# main.tf - EKS Cluster Module
###############################################

# EKS Cluster Role
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

# Cluster Security Group
resource "aws_security_group" "cluster" {
  count = var.create_cluster_security_group ? 1 : 0

  name_prefix = var.security_group_use_name_prefix ? local.cluster_security_group_name : null
  name        = var.security_group_use_name_prefix ? null : local.cluster_security_group_name
  description = "Security group for EKS cluster"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      "Name" = local.cluster_security_group_name
    }
  )
}

# Node Security Group
resource "aws_security_group" "node" {
  count = var.create_node_security_group ? 1 : 0

  name_prefix = var.security_group_use_name_prefix ? local.node_security_group_name : null
  name        = var.security_group_use_name_prefix ? null : local.node_security_group_name
  description = "Security group for EKS nodes"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      "Name" = local.node_security_group_name
    }
  )
}

# Cluster Security Group Rules
resource "aws_security_group_rule" "cluster" {
  for_each = var.create_cluster_security_group ? local.cluster_security_group_rules : {}

  security_group_id = aws_security_group.cluster[0].id
  description       = each.value.description
  type              = each.value.type
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_blocks       = lookup(each.value, "cidr_blocks", null)
  self              = lookup(each.value, "self", null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)
}

# Node Security Group Rules
resource "aws_security_group_rule" "node" {
  for_each = var.create_node_security_group ? local.node_security_group_rules : {}

  security_group_id = aws_security_group.node[0].id
  description       = each.value.description
  type              = each.value.type
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_blocks       = lookup(each.value, "cidr_blocks", null)
  self              = lookup(each.value, "self", null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)
}

# KMS Key for Cluster Encryption
resource "aws_kms_key" "cluster" {
  description             = "KMS key for EKS cluster encryption"
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = true

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-kms-key"
    }
  )
}

# EKS Cluster
resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = var.endpoint_private_access
    endpoint_public_access  = var.endpoint_public_access
    public_access_cidrs     = var.public_access_cidrs
    security_group_ids      = [aws_security_group.cluster[0].id]
  }

  kubernetes_network_config {
    service_ipv4_cidr = var.service_ipv4_cidr
    ip_family         = var.ip_family
  }

  enabled_cluster_log_types = var.enabled_cluster_log_types

  encryption_config {
    provider {
      key_arn = aws_kms_key.cluster.arn
    }
    resources = ["secrets"]
  }

  # Disable bootstrap creator admin permissions
  bootstrap_cluster_creator_admin_permissions = !var.disable_bootstrap_creator_admin

  tags = merge(
    var.tags,
    var.cluster_tags,
    {
      Name = var.cluster_name
    }
  )

  # Ensure IAM role permissions are created before cluster
  depends_on = [
    aws_iam_role_policy_attachment.cluster_policies,
    aws_cloudwatch_log_group.eks_logs
  ]

  lifecycle {
    # Prevent accidental cluster replacement
    prevent_destroy = false
    ignore_changes = [
      bootstrap_cluster_creator_admin_permissions
    ]
  }
}

# CloudWatch Log Group for EKS control plane logs
resource "aws_cloudwatch_log_group" "eks_logs" {
  count             = length(var.enabled_cluster_log_types) > 0 ? 1 : 0
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-logs"
    }
  )
}

# Access Entries
resource "aws_eks_access_entry" "this" {
  for_each = var.access_entries

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  type         = each.value.type

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
  for_each = {
    for entry_key, entry in var.access_entries : 
      "${entry_key}-${assoc_key}" => {
        entry_key = entry_key
        assoc     = assoc
      }
    for assoc_key, assoc in entry.policy_associations
  }

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_eks_access_entry.this[each.value.entry_key].principal_arn
  policy_arn    = each.value.assoc.policy_arn

  access_scope {
    type = each.value.assoc.access_scope.type
    namespaces = each.value.assoc.access_scope.type == "namespace" ? 
      each.value.assoc.access_scope.namespaces : null
  }

  depends_on = [
    aws_eks_access_entry.this
  ]
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

# Add-on Version Data Sources
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