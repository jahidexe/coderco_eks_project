# Default Security Group Rules
locals {
  default_cluster_security_group_rules = {
    allow_control_plane_ingress = {
      description              = "Allow control plane ingress"
      protocol                = "tcp"
      from_port               = 443
      to_port                 = 443
      type                    = "ingress"
      cidr_blocks             = ["0.0.0.0/0"]
    }
  }

  default_node_security_group_rules = {
    allow_node_ingress_self = {
      description              = "Allow nodes to communicate with each other"
      protocol                = "-1"
      from_port               = 0
      to_port                 = 0
      type                    = "ingress"
      self                    = true
    },
    allow_node_ingress_cluster = {
      description              = "Allow cluster to communicate with nodes"
      protocol                = "tcp"
      from_port               = 1025
      to_port                 = 65535
      type                    = "ingress"
      source_security_group_id = aws_security_group.cluster.id
    },
    allow_node_egress_all = {
      description  = "Allow all egress"
      protocol     = "-1"
      from_port    = 0
      to_port      = 0
      type         = "egress"
      cidr_blocks  = ["0.0.0.0/0"]
    }
  }

  # Merge default and custom rules
  cluster_security_group_rules = var.maintain_default_security_group_rules ? 
    merge(local.default_cluster_security_group_rules, var.cluster_security_group_rules) : 
    var.cluster_security_group_rules

  node_security_group_rules = var.maintain_default_security_group_rules ? 
    merge(local.default_node_security_group_rules, var.node_security_group_rules) : 
    var.node_security_group_rules

  # Security group name logic
  cluster_security_group_name = var.security_group_use_name_prefix ? 
    "${var.cluster_name}-cluster-sg-" : 
    "${var.cluster_name}-cluster-sg"

  node_security_group_name = var.security_group_use_name_prefix ? 
    "${var.cluster_name}-node-sg-" : 
    "${var.cluster_name}-node-sg"
} 