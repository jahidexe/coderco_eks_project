###############################################
# security.tf - EKS Security Group Configurations
###############################################

data "aws_subnets" "all" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
}

locals {
  # Use dynamic fallback to cover all subnets if none explicitly passed
  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.all.ids
}

# EKS Cluster Security Group


#checkov:skip=CKV2_AWS_5: "Security group is attached to EKS cluster via aws_eks_cluster.vpc_config.security_group_ids"
resource "aws_security_group" "cluster" {
  count = var.create_security_group ? 1 : 0
resource "aws_security_group" "cluster" {
  count = var.create_security_group ? 1 : 0

  name_prefix = "${local.names.cluster_sg}-"
  description = "EKS cluster security group with managed rules for cluster ${var.cluster_name}"
  vpc_id      = var.vpc_id

  tags = merge(
    local.resource_tags["cluster_sg"],
    {
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Node Security Group

#checkov:skip=CKV2_AWS_5: "Security group is attached to EKS launch template via vpc_security_group_ids"
resource "aws_security_group" "node" {
  count = var.create_security_group ? 1 : 0

  name_prefix = "${local.names.node_sg}-"
  description = "EKS node security group with managed rules for cluster ${var.cluster_name}"
  vpc_id      = var.vpc_id

  tags = merge(
    local.resource_tags["node_sg"],
    {
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# Add specific ingress/egress rules with proper descriptions
resource "aws_security_group_rule" "cluster_egress" {
  count = var.create_security_group ? 1 : 0

  description       = "Allow cluster egress access to node groups and endpoints"
  protocol          = "-1"
  security_group_id = aws_security_group.cluster[0].id
  cidr_blocks       = [var.vpc_cidr]
  from_port         = 0
  to_port           = 0
  type              = "egress"
}

# Node group egress rules with specific protocols and ports
resource "aws_security_group_rule" "node_egress_https" {
  count = var.create_security_group ? 1 : 0

  description       = "Allow node groups HTTPS egress for ECR and other HTTPS services"
  protocol          = "tcp"
  security_group_id = aws_security_group.node[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 443
  to_port           = 443
  type              = "egress"
}

resource "aws_security_group_rule" "node_egress_http" {
  count = var.create_security_group ? 1 : 0

  description       = "Allow node groups HTTP egress for package updates"
  protocol          = "tcp"
  security_group_id = aws_security_group.node[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 80
  to_port           = 80
  type              = "egress"
}

resource "aws_security_group_rule" "node_egress_ntp" {
  count = var.create_security_group ? 1 : 0

  description       = "Allow node groups NTP egress for time synchronization"
  protocol          = "udp"
  security_group_id = aws_security_group.node[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 123
  to_port           = 123
  type              = "egress"
}

resource "aws_security_group_rule" "node_egress_dns" {
  count = var.create_security_group ? 1 : 0

  description       = "Allow node groups DNS egress"
  protocol          = "udp"
  security_group_id = aws_security_group.node[0].id
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 53
  to_port           = 53
  type              = "egress"
}

resource "aws_security_group_rule" "node_egress_vpc" {
  count = var.create_security_group ? 1 : 0

  description       = "Allow node groups egress to VPC CIDR"
  protocol          = "-1"
  security_group_id = aws_security_group.node[0].id
  cidr_blocks       = [var.vpc_cidr]
  from_port         = 0
  to_port           = 0
  type              = "egress"
}

# Add cluster security group rules from locals
resource "aws_security_group_rule" "cluster_rules" {
  for_each = var.create_security_group ? local.cluster_security_group_rules : {}

  security_group_id        = aws_security_group.cluster[0].id
  description              = each.value.description
  type                     = each.value.type
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  protocol                 = each.value.protocol
  cidr_blocks              = try(each.value.cidr_blocks, null)
  source_security_group_id = try(each.value.source_security_group_id, null)
  self                     = try(each.value.self, null)
}
