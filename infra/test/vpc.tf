module "vpc" {
  source = "../modules/vpc"

  name        = var.name
  environment = var.environment
  region      = var.region

  vpc_cidr = var.vpc_cidr

  # VPC settings
  instance_tenancy     = var.instance_tenancy
  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames

  # Subnet settings - Two AZs for EKS requirements
  public_subnet_cidrs     = ["10.0.1.0/24", "10.0.2.0/24"]    # Two public subnets
  private_subnet_cidrs    = ["10.0.101.0/24", "10.0.102.0/24"] # Two private subnets
  azs                     = ["eu-west-1a", "eu-west-1b"]       # Two AZs
  map_public_ip_on_launch = var.map_public_ip_on_launch

  # NAT Gateway settings - Single NAT for testing
  enable_nat_gateway = var.enable_nat_gateway
  single_nat_gateway = true  # Use single NAT gateway for cost savings

  # Flow Log settings
  enable_flow_log          = var.enable_flow_log
  flow_log_destination_arn = var.flow_log_destination_arn

  # VPC Endpoint settings
  create_s3_endpoint = var.create_s3_endpoint

  # EKS settings
  create_eks_security_group = true  # Enable EKS security group
  eks_security_group_rules  = var.eks_security_group_rules
  cluster_name              = var.cluster_name
  subnet_tags_for_eks       = true  # Enable EKS subnet tags
  eks_subnet_annotations    = var.eks_subnet_annotations

  # Tags
  tags                = var.tags
  vpc_tags            = var.vpc_tags
  public_subnet_tags  = var.public_subnet_tags
  private_subnet_tags = var.private_subnet_tags
}
