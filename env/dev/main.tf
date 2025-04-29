module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=5f5df57" # v5.5.2

  name = "test-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["eu-west-1a", "eu-west-1b"]
  public_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnets = ["10.0.101.0/24", "10.0.102.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  create_igw           = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Enable VPC Flow Logs
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_max_aggregation_interval    = 60

  manage_default_network_acl     = true
  manage_default_route_table     = true
  manage_default_security_group  = true
  default_security_group_ingress = []
  default_security_group_egress  = []

  map_public_ip_on_launch = false

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "karpenter.sh/discovery"          = "test-vpc"
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = {
    Environment = "Test"
    Project     = "Terraform VPC"
  }

  vpc_security_group_ids = var.create_security_group ? [aws_security_group.node[0].id] : []
}

variable "map_public_ip_on_launch" {
  description = "Should be false if you do not want to auto-assign public IP on launch"
  type        = bool
  default     = false
}