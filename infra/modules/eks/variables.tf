###############################################
# variables.tf - EKS Cluster Module Variables
###############################################

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version to use for the EKS cluster"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC where the cluster will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the EKS cluster (should include both private and public subnets)"
  type        = list(string)
}

variable "endpoint_private_access" {
  description = "Whether the EKS private API server endpoint is enabled"
  type        = bool
  default     = true
}

variable "endpoint_public_access" {
  description = "Whether the EKS public API server endpoint is enabled"
  type        = bool
  default     = true
}

variable "public_access_cidrs" {
  description = "List of CIDR blocks that can access the EKS public API server endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "service_ipv4_cidr" {
  description = "The CIDR block to assign Kubernetes service IP addresses from"
  type        = string
  default     = null # Uses the default 172.20.0.0/16 when null
}

variable "ip_family" {
  description = "The IP family used to assign Kubernetes pod and service addresses"
  type        = string
  default     = "ipv4"
  validation {
    condition     = contains(["ipv4", "ipv6"], var.ip_family)
    error_message = "Valid values for ip_family are ipv4 and ipv6."
  }
}

variable "create_cluster_sg" {
  description = "Whether to create a security group for the cluster"
  type        = bool
  default     = true
}

variable "security_group_ids" {
  description = "List of security group IDs for the EKS cluster"
  type        = list(string)
  default     = []
}

variable "enabled_cluster_log_types" {
  description = "List of the desired control plane logging to enable"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "log_retention_days" {
  description = "Number of days to retain EKS logs in CloudWatch"
  type        = number
  default     = 90
}

variable "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt secrets in the EKS cluster (leave empty to create a new key)"
  type        = string
  default     = ""
}

variable "prevent_cluster_destroy" {
  description = "Whether to prevent accidental destruction of the EKS cluster"
  type        = bool
  default     = true
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}

variable "cluster_tags" {
  description = "Additional tags for the EKS cluster"
  type        = map(string)
  default     = {}
}

variable "egress_cidr_blocks" {
  description = "List of CIDR blocks for egress traffic from the EKS cluster"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "oidc_service_accounts" {
  description = "List of service accounts that can assume IAM roles via OIDC"
  type        = list(string)
  default     = ["system:serviceaccount:kube-system:aws-node"]
}

variable "kms_key_deletion_window" {
  description = "Duration in days after which the KMS key is deleted after destruction of the resource"
  type        = number
  default     = 30
}

variable "cluster_policies" {
  description = "List of IAM policy ARNs to attach to the EKS cluster role"
  type        = list(string)
  default     = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  ]
}

# Node Group Variables
variable "managed_node_groups" {
  description = "Map of managed node group configurations"
  type = map(object({
    name                 = string
    instance_types      = list(string)
    min_size            = number
    max_size            = number
    desired_size        = number
    capacity_type       = string
    ami_type            = string
    disk_size           = number
    labels              = map(string)
    taints              = list(object({
      key    = string
      value  = string
      effect = string
    }))
    update_config = object({
      max_unavailable_percentage = number
    })
    tags = map(string)
  }))
  default = {}
}

variable "fargate_profiles" {
  description = "Map of Fargate profile configurations"
  type = map(object({
    name = string
    selectors = list(object({
      namespace = string
      labels    = map(string)
    }))
    subnet_ids = list(string)
    tags       = map(string)
  }))
  default = {}
}

# Add-ons Variables
variable "enable_vpc_cni" {
  description = "Whether to enable the VPC CNI add-on"
  type        = bool
  default     = true
}

variable "enable_coredns" {
  description = "Whether to enable the CoreDNS add-on"
  type        = bool
  default     = true
}

variable "enable_kube_proxy" {
  description = "Whether to enable the kube-proxy add-on"
  type        = bool
  default     = true
}

variable "enable_aws_load_balancer_controller" {
  description = "Whether to enable the AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "enable_ebs_csi_driver" {
  description = "Whether to enable the EBS CSI Driver"
  type        = bool
  default     = true
}

variable "enable_metrics_server" {
  description = "Whether to enable the Metrics Server"
  type        = bool
  default     = true
}

# Security Variables
variable "enable_network_policy" {
  description = "Whether to enable network policy support"
  type        = bool
  default     = true
}

variable "pod_security_standards" {
  description = "Configuration for pod security standards"
  type = object({
    enabled = bool
    mode    = string
  })
  default = {
    enabled = true
    mode    = "baseline"
  }
}

# Observability Variables
variable "enable_container_insights" {
  description = "Whether to enable Container Insights"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_metrics" {
  description = "Whether to enable CloudWatch metrics collection"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logs" {
  description = "Whether to enable CloudWatch logs collection"
  type        = bool
  default     = true
}

variable "node_security_group_additional_rules" {
  description = "Additional security group rules for worker nodes"
  type = map(object({
    description = string
    protocol    = string
    from_port   = number
    to_port     = number
    type        = string
    cidr_blocks = list(string)
  }))
  default = {}
}

variable "enable_prometheus" {
  description = "Whether to enable Prometheus monitoring"
  type        = bool
  default     = false
}

variable "enable_grafana" {
  description = "Whether to enable Grafana dashboard"
  type        = bool
  default     = false
}

variable "enable_irsa" {
  description = "Whether to enable IAM Roles for Service Accounts (IRSA)"
  type        = bool
  default     = true
}

variable "region" {
  description = "AWS region"
  type        = string
}