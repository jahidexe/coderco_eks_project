###############################################
# security.tf - EKS Security Configurations
###############################################

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
  
  # Ensure subnet_ids is always a valid list even if var.subnet_ids is empty
  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : []
}

# Node Security Group
resource "aws_security_group" "node" {
  name        = "${var.cluster_name}-node-sg"
  description = "Security group for EKS worker nodes"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-node-sg" }
  )
}

# Node Security Group Rules
resource "aws_security_group_rule" "node_ingress_self" {
  description              = "Allow nodes to communicate with each other"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.node.id
  source_security_group_id = aws_security_group.node.id
  type                     = "ingress"
}

resource "aws_security_group_rule" "node_ingress_cluster" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  security_group_id        = aws_security_group.node.id
  source_security_group_id = aws_security_group.cluster[0].id
  type                     = "ingress"
}

# Restrict egress to specific CIDR ranges and ports
resource "aws_security_group_rule" "node_egress_internet" {
  description       = "Allow nodes to communicate with the internet for updates"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.node.id
  cidr_blocks       = [var.vpc_cidr]
  type              = "egress"
}

resource "aws_security_group_rule" "node_egress_dns" {
  description       = "Allow nodes to communicate with DNS"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  security_group_id = aws_security_group.node.id
  cidr_blocks       = [var.vpc_cidr]
  type              = "egress"
}

# Additional Node Security Group Rules
resource "aws_security_group_rule" "node_additional_rules" {
  for_each = var.node_security_group_additional_rules

  description       = each.value.description
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  security_group_id = aws_security_group.node.id
  cidr_blocks       = each.value.cidr_blocks
  type              = each.value.type
}

# Network Policy Configuration
resource "aws_eks_addon" "vpc_cni" {
  count = var.enable_network_policy ? 1 : 0
  
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "vpc-cni"
  addon_version = var.vpc_cni_version

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-vpc-cni-addon" }
  )
}

resource "aws_eks_addon" "kube_proxy" {
  count = var.enable_network_policy ? 1 : 0
  
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "kube-proxy"
  addon_version = var.kube_proxy_version

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-kube-proxy-addon" }
  )
}

resource "aws_eks_addon" "coredns" {
  count = var.enable_network_policy ? 1 : 0
  
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "coredns"
  addon_version = var.coredns_version

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-coredns-addon" }
  )
}

# Pod Security Standards Configuration
resource "kubernetes_namespace" "baseline" {
  count = var.pod_security_standards.enabled ? 1 : 0

  metadata {
    name = "baseline"
    labels = {
      "pod-security.kubernetes.io/enforce" = "baseline"
      "pod-security.kubernetes.io/warn"    = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
    }
  }
}

resource "kubernetes_namespace" "restricted" {
  count = var.pod_security_standards.enabled ? 1 : 0

  metadata {
    name = "restricted"
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
    }
  }
}

# Container Insights Configuration
resource "aws_cloudwatch_log_group" "container_insights" {
  count             = var.enable_container_insights ? 1 : 0
  name              = "/aws/containerinsights/${var.cluster_name}/application"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-container-insights" }
  )
}

# CloudWatch Agent Configuration
resource "aws_iam_role" "cloudwatch_agent" {
  count = var.enable_cloudwatch_metrics ? 1 : 0
  name  = "${var.cluster_name}-cloudwatch-agent"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-cloudwatch-agent" }
  )
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  count      = var.enable_cloudwatch_metrics ? 1 : 0
  role       = aws_iam_role.cloudwatch_agent[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Cluster Security Group Rules
resource "aws_security_group_rule" "cluster_egress_internet" {
  description       = "Allow cluster to communicate with the internet"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.cluster[0].id
  cidr_blocks       = [var.vpc_cidr]
  type              = "egress"
}

resource "aws_security_group_rule" "cluster_egress_dns" {
  description       = "Allow cluster to communicate with DNS"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  security_group_id = aws_security_group.cluster[0].id
  cidr_blocks       = [var.vpc_cidr]
  type              = "egress"
}

# Network ACL with explicit subnet associations
resource "aws_network_acl" "eks" {
  vpc_id     = var.vpc_id
  subnet_ids = local.subnet_ids  # Explicitly associate all subnets with NACL

  # Generate ingress rules dynamically
  dynamic "ingress" {
    for_each = local.nacl_rules.ingress
    
    content {
      protocol   = ingress.value.protocol
      rule_no    = ingress.value.rule_no
      action     = ingress.value.action
      cidr_block = ingress.value.cidr_block
      from_port  = ingress.value.from_port
      to_port    = ingress.value.to_port
    }
  }

  # Generate egress rules dynamically
  dynamic "egress" {
    for_each = local.nacl_rules.egress
    
    content {
      protocol   = egress.value.protocol
      rule_no    = egress.value.rule_no
      action     = egress.value.action
      cidr_block = egress.value.cidr_block
      from_port  = egress.value.from_port
      to_port    = egress.value.to_port
    }
  }

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-network-acl" }
  )
  
  # Explicitly create before any associations might be attempted
  lifecycle {
    create_before_destroy = true
  }
}

# Default Security Group (lock down default SG)
resource "aws_default_security_group" "default" {
  vpc_id = var.vpc_id  # Use the variable instead of aws_vpc.main.id

  # Block all ingress traffic
  ingress {
    protocol         = "-1"
    self             = false
    from_port        = 0
    to_port          = 0
    cidr_blocks      = []
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
  }

  # Block all egress traffic
  egress {
    protocol         = "-1"
    from_port        = 0
    to_port          = 0
    cidr_blocks      = []
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    self             = false
  }

  tags = merge(
    var.tags,
    { Name = "${var.cluster_name}-default-sg" }
  )
}