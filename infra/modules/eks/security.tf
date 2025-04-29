###############################################
# security.tf - Consolidated EKS Security Configurations
###############################################

data "aws_subnets" "all" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
}

locals {
  # Define NACL rules in a structured map for reusability
  nacl_rules = {
    ingress = [
      {
        rule_no    = 300
        protocol   = "tcp"
        action     = "allow"
        cidr_block = var.vpc_cidr
        from_port  = 1025
        to_port    = 65535
        description = "Allow ephemeral ports ingress from VPC CIDR"
      },
      {
        rule_no    = 200
        protocol   = "-1"
        action     = "allow"
        cidr_block = var.vpc_cidr
        from_port  = 0
        to_port    = 0
        description = "Allow pod-to-pod communication"
      },
      {
        rule_no    = 100
        protocol   = "tcp"
        action     = "allow"
        cidr_block = var.vpc_cidr
        from_port  = 443
        to_port    = 443
        description = "Allow return traffic from established connections"
      },
      {
        rule_no    = 32766
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
        description = "Deny all other ingress traffic"
      }
    ],
    egress = [
      {
        rule_no    = 100
        protocol   = "tcp"
        action     = "allow"
        cidr_block = var.vpc_cidr
        from_port  = 443
        to_port    = 443
        description = "Allow HTTPS egress to VPC CIDR"
      },
      {
        rule_no    = 200
        protocol   = "udp"
        action     = "allow"
        cidr_block = var.vpc_cidr
        from_port  = 53
        to_port    = 53
        description = "Allow DNS egress to VPC CIDR"
      },
      {
        rule_no    = 32766
        protocol   = "-1"
        action     = "deny"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        to_port    = 0
        description = "Deny all other egress traffic"
      }
    ]
  }

  # Node security group rules
  node_security_group_rules = var.create_node_security_group ? {
    ingress_self = {
      description              = "Allow nodes to communicate with each other"
      from_port                = 0
      to_port                  = 0
      protocol                 = "-1"
      type                     = "ingress"
      self                     = true
    }
    ingress_cluster = {
      description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
      from_port                = 1025
      to_port                  = 65535
      protocol                 = "tcp"
      type                     = "ingress"
      source_security_group_id = aws_security_group.cluster.id
    }
    egress_https = {
      description       = "Allow nodes to communicate with the internet for updates"
      from_port         = 443
      to_port           = 443
      protocol          = "tcp"
      type              = "egress"
      cidr_blocks       = [var.vpc_cidr]
    }
    egress_dns = {
      description       = "Allow nodes to communicate with DNS"
      from_port         = 53
      to_port           = 53
      protocol          = "udp"
      type              = "egress"
      cidr_blocks       = [var.vpc_cidr]
    }
  } : {}

  # Cluster security group rules
  cluster_security_group_rules = var.create_cluster_security_group ? {
    ingress_https = {
      description = "Allow HTTPS inbound traffic"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      type        = "ingress"
      cidr_blocks = [var.vpc_cidr]
    }
    egress_https = {
      description = "Allow HTTPS outbound traffic"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
    egress_dns = {
      description = "Allow DNS outbound traffic"
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
    egress_ntp = {
      description = "Allow NTP outbound traffic"
      from_port   = 123
      to_port     = 123
      protocol    = "udp"
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
  } : {}

  # Use dynamic fallback to cover all subnets if none explicitly passed
  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.all.ids

  # Create node security group name
  node_security_group_name = "${var.cluster_name}-node-sg"
}

# ... (Rest of your security.tf remains unchanged)
