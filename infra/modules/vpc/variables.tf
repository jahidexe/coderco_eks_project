


###############################################
# variables.tf - VPC Module Variables
###############################################

variable "name" {
  description = "Name to be used on all resources as prefix"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
}

variable "azs" {
  description = "A list of availability zones in the region"
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "A list of public subnet CIDRs"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "A list of private subnet CIDRs"
  type        = list(string)
}

variable "instance_tenancy" {
  description = "A tenancy option for instances launched into the VPC"
  type        = string
  default     = "default"
}

variable "enable_dns_hostnames" {
  description = "Should be true to enable DNS hostnames in the VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Should be true to enable DNS support in the VPC"
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

variable "map_public_ip_on_launch" {
  description = "Should be true if you want to auto-assign public IP on launch for public subnets"
  type        = bool
  default     = true
}

variable "enable_flow_log" {
  description = "Whether or not to enable VPC Flow Logs"
  type        = bool
  default     = false
}

variable "flow_log_destination_arn" {
  description = "The ARN of the S3 bucket where VPC Flow Logs will be pushed"
  type        = string
  default     = ""
}

variable "create_s3_endpoint" {
  description = "Whether to create an S3 endpoint within the VPC"
  type        = bool
  default     = false
}

variable "create_eks_security_group" {
  description = "Whether to create a security group for EKS"
  type        = bool
  default     = true
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = ""
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
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
  description = "Whether to add Kubernetes-specific tags to subnets"
  type        = bool
  default     = true
}

variable "eks_subnet_annotations" {
  description = "Additional Kubernetes annotations to add to subnets"
  type        = map(string)
  default     = {}
}

variable "environment" {
  description = "Environment name, used as part of the resource naming"
  type        = string
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