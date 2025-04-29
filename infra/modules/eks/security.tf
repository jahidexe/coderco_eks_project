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
  protocol         = "-1"
  security_group_id = aws_security_group.cluster[0].id
  cidr_blocks      = [var.vpc_cidr]
  from_port        = 0
  to_port          = 0
  type             = "egress"
}

resource "aws_security_group_rule" "node_egress" {
  count = var.create_security_group ? 1 : 0

  description       = "Allow node groups egress access to internet for updates and package installation"
  protocol         = "-1"
  security_group_id = aws_security_group.node[0].id
  cidr_blocks      = ["0.0.0.0/0"]
  from_port        = 0
  to_port          = 0
  type             = "egress"
}

# Add other security group rules from locals with proper descriptions
dynamic "aws_security_group_rule" "cluster_rules" {
  for_each = local.cluster_security_group_rules

  content {
    security_group_id = aws_security_group.cluster[0].id
    description       = each.value.description
    type             = each.value.type
    from_port        = each.value.from_port
    to_port          = each.value.to_port
    protocol         = each.value.protocol
    cidr_blocks      = try(each.value.cidr_blocks, null)
    source_security_group_id = try(each.value.source_security_group_id, null)
    self             = try(each.value.self, null)
  }
}
