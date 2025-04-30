###############################################
# locals.tf - EKS Module Local Values - Type Safe
###############################################

locals {
  # Base security group rule type definition - moved to variables.tf

  # Common naming convention
  names = {
    cluster_sg   = var.security_group_use_name_prefix ? "${var.cluster_name}-cluster-sg-" : "${var.cluster_name}-cluster-sg"
    node_sg      = var.security_group_use_name_prefix ? "${var.cluster_name}-node-sg-" : "${var.cluster_name}-node-sg"
    cluster_role = "${var.cluster_name}-cluster-role"
    node_role    = "${var.cluster_name}-node-role"
    kms_key      = "${var.cluster_name}-cluster-key"
    log_group    = "/aws/eks/${var.cluster_name}/cluster"
  }

  # Common tag structure
  tags = merge(
    var.tags,
    {
      "kubernetes.io/cluster/${var.cluster_name}" = "owned"
      ManagedBy                                   = "terraform"
      Cluster                                     = var.cluster_name
    }
  )

  # Common tag structure for resources
  resource_tags = {
    for key, name in local.names : key => merge(
      local.tags,
      { Name = name }
    )
  }

  # Default security rules with consistent types
  default_rules = {
    cluster = {
      api_access = {
        type        = "ingress"
        protocol    = "tcp"
        from_port   = 443
        to_port     = 443
        description = "Allow API access"
        cidr_blocks = [var.vpc_cidr]
        self        = null
      }
    }
    nodes = {
      internal_communication = {
        type        = "ingress"
        protocol    = "tcp"
        from_port   = 443
        to_port     = 443
        description = "Allow internal communication"
        cidr_blocks = null
        self        = true
      }
    }
  }

  # VPC Endpoint configurations
  vpc_endpoints = {
    eks = {
      service = "eks"
      type    = "Interface"
    }
    ecr_api = {
      service = "ecr.api"
      type    = "Interface"
    }
    ecr_dkr = {
      service = "ecr.dkr"
      type    = "Interface"
    }
  }

  # Add-on configurations
  addons = {
    vpc_cni = {
      name    = "vpc-cni"
      enabled = var.enable_vpc_cni
    }
    coredns = {
      name    = "coredns"
      enabled = var.enable_coredns
    }
    kube_proxy = {
      name    = "kube-proxy"
      enabled = var.enable_kube_proxy
    }
    ebs_csi = {
      name    = "aws-ebs-csi-driver"
      enabled = var.enable_ebs_csi_driver
    }
  }

  # Ensure custom rules have same type structure
  custom_cluster_rules = {
    for k, v in var.cluster_security_group_rules : k => merge(
      {
        type        = "ingress"
        protocol    = "-1"
        from_port   = 0
        to_port     = 0
        description = "Custom rule ${k}"
        cidr_blocks = null
        self        = null
      },
      v
    )
  }

  custom_node_rules = {
    for k, v in var.node_security_group_rules : k => merge(
      {
        type        = "ingress"
        protocol    = "-1"
        from_port   = 0
        to_port     = 0
        description = "Custom rule ${k}"
        cidr_blocks = null
        self        = null
      },
      v
    )
  }

  # Final security rules with consistent types
  cluster_security_group_rules = var.maintain_default_security_group_rules ? merge(local.default_rules.cluster, local.custom_cluster_rules) : local.custom_cluster_rules
  node_security_group_rules    = var.maintain_default_security_group_rules ? merge(local.default_rules.nodes, local.custom_node_rules) : local.custom_node_rules

  # Feature flags with consistent types
  features = {
    encryption_enabled = var.kms_key_arn != null && var.kms_key_arn != ""
    logging_enabled    = length(coalesce(var.enabled_cluster_log_types, [])) > 0
    private_access     = true
    public_access      = false
  }
}