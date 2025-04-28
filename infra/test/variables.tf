variable "name" {
  description = "Name to be used on all the resources as identifier"
  type        = string
  default     = "test-eks"
}

variable "environment" {
  description = "Environment name, used as part of the resource naming"
  type        = string
  default     = "test"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_tenancy" {
  description = "A tenancy option for instances launched into the VPC"
  type        = string
  default     = "default"
}

variable "enable_dns_support" {
  description = "Should be true to enable DNS support in the VPC"
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = "Should be true to enable DNS hostnames in the VPC"
  type        = bool
  default     = true
}

variable "public_subnet_cidrs" {
  description = "A list of public subnet CIDRs to deploy inside the VPC"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "A list of private subnet CIDRs to deploy inside the VPC"
  type        = list(string)
}

variable "azs" {
  description = "A list of Availability zones in the region"
  type        = list(string)
}

variable "map_public_ip_on_launch" {
  description = "Should be false if you do not want to auto-assign public IP on launch"
  type        = bool
  default     = true
}

variable "enable_nat_gateway" {
  description = "Should be true if you want to provision NAT Gateways for each of your private networks"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Should be true if you want to provision a single shared NAT Gateway across all of your private networks"
  type        = bool
  default     = false
}

variable "enable_flow_log" {
  description = "Whether or not to enable VPC Flow Logs"
  type        = bool
  default     = false
}

variable "flow_log_destination_arn" {
  description = "The ARN of the CloudWatch log group or S3 bucket where VPC Flow Logs will be pushed"
  type        = string
  default     = ""
}

variable "create_s3_endpoint" {
  description = "Whether to create an S3 VPC endpoint"
  type        = bool
  default     = true
}

variable "create_eks_security_group" {
  description = "Whether to create an EKS security group"
  type        = bool
  default     = false
}

variable "eks_security_group_rules" {
  description = "List of security group rules for EKS cluster"
  type = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default = []
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {
    Environment = "test"
    ManagedBy   = "Terraform"
    Project     = "eks-test"
  }
}

variable "vpc_tags" {
  description = "Additional tags for the VPC"
  type        = map(string)
  default     = {}
}

variable "public_subnet_tags" {
  description = "Additional tags for the public subnets"
  type        = map(string)
  default     = {}
}

variable "private_subnet_tags" {
  description = "Additional tags for the private subnets"
  type        = map(string)
  default     = {}
}

variable "subnet_tags_for_eks" {
  description = "Whether to add EKS-specific tags to subnets"
  type        = bool
  default     = false
}

variable "eks_subnet_annotations" {
  description = "Additional EKS subnet annotations"
  type        = map(string)
  default     = {}
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "test-eks-cluster"
}

variable "terraform_version" {
  description = "Required Terraform version"
  type        = string
  default     = ">= 1.0.0"
}

variable "aws_provider_version" {
  description = "Required AWS provider version"
  type        = string
  default     = ">= 4.0.0"
}

# EKS Cluster Configuration
variable "eks_service_ipv4_cidr" {
  description = "The CIDR block to assign Kubernetes service IP addresses from"
  type        = string
}

variable "eks_ip_family" {
  description = "The IP family used to assign Kubernetes pod and service IP addresses"
  type        = string
}

# EKS Access Configuration
variable "eks_endpoint_private_access" {
  description = "Indicates whether or not the Amazon EKS private API server endpoint is enabled"
  type        = bool
}

variable "eks_endpoint_public_access" {
  description = "Indicates whether or not the Amazon EKS public API server endpoint is enabled"
  type        = bool
}

variable "eks_public_access_cidrs" {
  description = "List of CIDR blocks which can access the Amazon EKS public API server endpoint"
  type        = list(string)
}

# EKS Logging Configuration
variable "eks_enabled_cluster_log_types" {
  description = "A list of the desired control plane logging to enable"
  type        = list(string)
}

variable "eks_log_retention_days" {
  description = "Number of days to retain log events"
  type        = number
}

# EKS Security Configuration
variable "eks_prevent_cluster_destroy" {
  description = "If true, will prevent the cluster from being destroyed"
  type        = bool
}

# EKS Tags
variable "eks_cluster_tags" {
  description = "Additional tags for the EKS cluster"
  type        = map(string)
}

# EKS IAM Configuration
variable "eks_cluster_policies" {
  description = "List of IAM policy ARNs to attach to the EKS cluster role"
  type        = list(string)
  default = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  ]
}

# AWS Provider Configuration
variable "aws_max_retries" {
  description = "Maximum number of retries for AWS API calls"
  type        = number
  default     = 3
}

variable "aws_shared_credentials_file" {
  description = "Path to the shared credentials file"
  type        = string
  default     = "~/.aws/credentials"
}

variable "aws_endpoints" {
  description = "Custom AWS endpoints configuration"
  type        = map(string)
  default     = {}
}

variable "aws_profile" {
  description = "AWS profile to use for authentication"
  type        = string
  default     = "default"
}
