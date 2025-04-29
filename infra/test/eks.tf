###############################################
# eks.tf - EKS Module Test Implementation
###############################################

module "eks" {
  source = "../modules/eks"

  # Cluster Configuration
  cluster_name       = "test-eks-cluster"
  kubernetes_version = "1.28"
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = concat(module.vpc.private_subnet_ids, module.vpc.public_subnet_ids)
  region             = var.region

  # Node Groups Configuration - Single node group for testing
  managed_node_groups = {
    test = {
      name           = "test"
      instance_types = ["t3.small"]  # Smaller instance for testing
      min_size       = 1
      max_size       = 1
      desired_size   = 1
      capacity_type  = "ON_DEMAND"
      ami_type       = "AL2_x86_64"
      disk_size      = 20
      labels         = {
        environment = "test"
      }
      taints         = []
      update_config = {
        max_unavailable_percentage = 50
      }
      tags = {
        Environment = "test"
        Terraform   = "true"
      }
    }
  }

  # Fargate Profiles - Disabled for testing
  fargate_profiles = {}

  # Add-ons Configuration - Minimal for testing
  enable_vpc_cni                      = true
  enable_coredns                      = true
  enable_kube_proxy                   = true
  enable_aws_load_balancer_controller = false  # Disabled for testing
  enable_ebs_csi_driver               = false  # Disabled for testing
  enable_metrics_server               = false  # Disabled for testing

  # Security Configuration
  enable_network_policy = false  # Disabled for testing
  pod_security_standards = {
    enabled = false  # Disabled for testing
    mode    = "baseline"
  }

  # Observability Configuration - Minimal for testing
  enable_container_insights = false
  enable_cloudwatch_metrics = false
  enable_cloudwatch_logs    = false

  # Additional Security Group Rules - Simplified to avoid duplicates
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      cidr_blocks = [module.vpc.vpc_cidr_block]
    }
  }

  # Tags
  tags = merge(
    var.tags,
    {
      Environment = "test"
      Terraform   = "true"
      Project     = "eks-test"
    }
  )
}

# Outputs
output "cluster_id" {
  description = "The ID of the EKS cluster"
  value       = module.eks.cluster_id
}

output "cluster_endpoint" {
  description = "The endpoint for the EKS API server"
  value       = module.eks.cluster_endpoint
}

output "node_group_arns" {
  description = "ARNs of the EKS node groups"
  value       = module.eks.node_group_arns
}

output "fargate_profile_arns" {
  description = "ARNs of the EKS Fargate profiles"
  value       = module.eks.fargate_profile_arns
}
