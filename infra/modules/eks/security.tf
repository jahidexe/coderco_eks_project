###############################################
# security.tf - EKS Security Configurations
###############################################

# Node Security Group
resource "aws_security_group" "node" {
  name        = "${var.cluster_name}-node-sg"
  description = "Security group for EKS worker nodes"
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-node-sg"
    }
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
  source_security_group_id = aws_security_group.cluster.id
  type                     = "ingress"
}

# Restrict egress to specific CIDR ranges and ports
resource "aws_security_group_rule" "node_egress_internet" {
  description       = "Allow nodes to communicate with the internet for updates"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.node.id
  cidr_blocks       = ["10.0.0.0/16"]  # Restrict to VPC CIDR
  type              = "egress"
}

resource "aws_security_group_rule" "node_egress_dns" {
  description       = "Allow nodes to communicate with DNS"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  security_group_id = aws_security_group.node.id
  cidr_blocks       = ["10.0.0.0/16"]  # Restrict to VPC CIDR
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
resource "aws_eks_cluster" "network_policy" {
  count = var.enable_network_policy ? 1 : 0

  name     = aws_eks_cluster.this.name
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = var.endpoint_private_access
    endpoint_public_access  = var.endpoint_public_access
    public_access_cidrs     = var.public_access_cidrs
    security_group_ids      = [aws_security_group.cluster.id]
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

  tags = merge(
    var.tags,
    var.cluster_tags,
    {
      Name = var.cluster_name
    }
  )

  depends_on = [
    aws_iam_role_policy_attachment.cluster_policies,
    aws_cloudwatch_log_group.eks_logs
  ]
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
  count = var.enable_container_insights ? 1 : 0

  name              = "/aws/containerinsights/${var.cluster_name}/application"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-container-insights"
    }
  )
}

# CloudWatch Agent Configuration
resource "aws_iam_role" "cloudwatch_agent" {
  count = var.enable_cloudwatch_metrics ? 1 : 0

  name = "${var.cluster_name}-cloudwatch-agent"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-cloudwatch-agent"
    }
  )
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  count = var.enable_cloudwatch_metrics ? 1 : 0

  role       = aws_iam_role.cloudwatch_agent[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Cluster Security Group Rules
resource "aws_security_group_rule" "cluster_egress_internet" {
  description       = "Allow cluster to communicate with the internet"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.cluster.id
  cidr_blocks       = ["10.0.0.0/16"]  # Restrict to VPC CIDR
  type              = "egress"
}

resource "aws_security_group_rule" "cluster_egress_dns" {
  description       = "Allow cluster to communicate with DNS"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  security_group_id = aws_security_group.cluster.id
  cidr_blocks       = ["10.0.0.0/16"]  # Restrict to VPC CIDR
  type              = "egress"
}

# Network ACL
resource "aws_network_acl" "eks" {
  vpc_id = var.vpc_id

  # Allow HTTPS egress to VPC CIDR
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 443
    to_port    = 443
  }

  # Allow DNS egress to VPC CIDR
  egress {
    protocol   = "udp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 53
    to_port    = 53
  }

  # Allow ephemeral ports ingress from VPC CIDR
  ingress {
    protocol   = "tcp"
    rule_no    = 300
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 1025
    to_port    = 65535
  }

  # Deny all other ingress traffic
  ingress {
    protocol   = "-1"
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Deny all other egress traffic
  egress {
    protocol   = "-1"
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-network-acl"
    }
  )
}

# Network ACL Associations
resource "aws_network_acl_association" "eks" {
  for_each = toset(var.subnet_ids)

  network_acl_id = aws_network_acl.eks.id
  subnet_id      = each.value
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
