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
  count = var.create_cluster_security_group ? 1 : 0

  name        = local.names.cluster_sg
  description = "Security group for EKS cluster ${var.cluster_name}"
  vpc_id      = var.vpc_id

  tags = local.resource_tags["cluster_sg"]
}

# Node Security Group
resource "aws_security_group" "node" {
  count = var.create_node_security_group ? 1 : 0

  name        = local.names.node_sg
  description = "Security group for EKS nodes"
  vpc_id      = var.vpc_id

  tags = local.resource_tags["node_sg"]
}

# Cluster Security Group Rules
resource "aws_security_group_rule" "cluster" {
  for_each = var.create_cluster_security_group ? local.security_rules.cluster : {}

  security_group_id        = aws_security_group.cluster[0].id
  type                     = each.value.type
  protocol                 = each.value.protocol
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  self                     = lookup(each.value, "self", null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)

  description = each.value.description
}

# Node Security Group Rules
resource "aws_security_group_rule" "node" {
  for_each = var.create_node_security_group ? local.security_rules.nodes : {}

  security_group_id        = aws_security_group.node[0].id
  type                     = each.value.type
  protocol                 = each.value.protocol
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  self                     = lookup(each.value, "self", null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)

  description = each.value.description
}
