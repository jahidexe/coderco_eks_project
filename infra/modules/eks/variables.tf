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

  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "At least one subnet ID must be provided for the EKS cluster."
  }
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

variable "create_cluster_security_group" {
  description = "Whether to create a security group for the EKS cluster"
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
  default = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  ]
}

# Node Group Variables
variable "managed_node_groups" {
  description = "Map of managed node group configurations"
  type = map(object({
    name           = string
    instance_types = list(string)
    min_size       = number
    max_size       = number
    desired_size   = number
    capacity_type  = string
    ami_type       = string
    disk_size      = number
    labels         = map(string)
    taints = list(object({
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
  description = "Enable VPC CNI add-on"
  type        = bool
  default     = true
}

variable "enable_coredns" {
  description = "Enable CoreDNS add-on"
  type        = bool
  default     = true
}

variable "enable_kube_proxy" {
  description = "Enable kube-proxy add-on"
  type        = bool
  default     = true
}

variable "enable_aws_load_balancer_controller" {
  description = "Whether to enable the AWS Load Balancer Controller"
  type        = bool
  default     = true
}

variable "enable_ebs_csi_driver" {
  description = "Enable EBS CSI Driver add-on"
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
    exemptions = object({
      usernames      = list(string)
      runtimeClasses = list(string)
      namespaces     = list(string)
    })
  })
  default = {
    enabled = true
    mode    = "restricted"
    exemptions = {
      usernames      = []
      runtimeClasses = []
      namespaces     = ["kube-system"]
    }
  }
}

variable "pod_security_context" {
  description = "Default security context for pods"
  type = object({
    run_as_non_root = bool
    run_as_user     = number
    run_as_group    = number
    fs_group        = number
  })
  default = {
    run_as_non_root = true
    run_as_user     = 1000
    run_as_group    = 3000
    fs_group        = 2000
  }
}

variable "container_security_context" {
  description = "Default security context for containers"
  type = object({
    allow_privilege_escalation = bool
    read_only_root_filesystem  = bool
    capabilities = object({
      add  = list(string)
      drop = list(string)
    })
  })
  default = {
    allow_privilege_escalation = false
    read_only_root_filesystem  = true
    capabilities = {
      add  = []
      drop = ["ALL"]
    }
  }
}

variable "runtime_security" {
  description = "Configuration for runtime security"
  type = object({
    enabled = bool
    falco = object({
      enabled = bool
      config  = map(string)
    })
  })
  default = {
    enabled = true
    falco = {
      enabled = true
      config = {
        file_output_enabled = true
        json_output         = true
        syslog_output       = true
        priority            = "debug"
      }
    }
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

# Access Entries Variables
variable "access_entries" {
  description = "Map of EKS cluster access entries defining which IAM principals can access the cluster and their permissions"
  type = map(object({
    principal_arn     = string                       # The IAM ARN of the user or role
    kubernetes_groups = optional(list(string))       # Kubernetes RBAC groups
    type              = optional(string, "STANDARD") # Access entry type
    policy_associations = map(object({
      policy_arn = string # EKS access policy ARN to associate
      access_scope = object({
        type       = string                 # "cluster" or "namespace" 
        namespaces = optional(list(string)) # Required if type is "namespace"
      })
    }))
  }))
  default = {}

  validation {
    condition     = length(var.access_entries) > 0
    error_message = "At least one access entry must be provided for the cluster."
  }

  validation {
    condition = alltrue([
      for entry in var.access_entries : contains(["STANDARD", "FARGATE_LINUX", "EC2_LINUX", "EC2_WINDOWS"], entry.type)
    ])
    error_message = "Access entry type must be one of: STANDARD, FARGATE_LINUX, EC2_LINUX, EC2_WINDOWS"
  }

  validation {
    condition = alltrue([
      for entry in var.access_entries : alltrue([
        for assoc in entry.policy_associations : contains(["cluster", "namespace"], assoc.access_scope.type)
      ])
    ])
    error_message = "Access scope type must be either 'cluster' or 'namespace'"
  }

  validation {
    condition = alltrue([
      for entry in var.access_entries : alltrue([
        for assoc in entry.policy_associations :
        assoc.access_scope.type != "namespace" || length(assoc.access_scope.namespaces) > 0
      ])
    ])
    error_message = "Namespaces must be specified when access scope type is 'namespace'"
  }
}

variable "disable_bootstrap_creator_admin" {
  description = "Disable bootstrap cluster creator admin permissions"
  type        = bool
  default     = true
}

variable "addon_version_preferences" {
  description = "Version preferences for EKS add-ons"
  type = object({
    vpc_cni    = string
    coredns    = string
    kube_proxy = string
    ebs_csi    = string
  })
  default = {
    vpc_cni    = "latest"
    coredns    = "latest"
    kube_proxy = "latest"
    ebs_csi    = "latest"
  }
}

variable "addon_configurations" {
  description = "Configuration values for EKS add-ons"
  type = object({
    vpc_cni    = map(string)
    coredns    = map(string)
    kube_proxy = map(string)
    ebs_csi    = map(string)
  })
  default = {
    vpc_cni    = {}
    coredns    = {}
    kube_proxy = {}
    ebs_csi    = {}
  }
}

variable "addon_conflict_resolution" {
  description = "Conflict resolution strategy for add-ons"
  type = object({
    on_create = string
    on_update = string
  })
  default = {
    on_create = "OVERWRITE"
    on_update = "OVERWRITE"
  }
}

variable "addon_timeouts" {
  description = "Timeout configuration for add-on operations"
  type = object({
    create = string
    update = string
    delete = string
  })
  default = {
    create = "20m"
    update = "20m"
    delete = "20m"
  }
}

variable "addon_tags" {
  description = "Additional tags to apply to add-ons"
  type        = map(string)
  default     = {}
}

# Security Group Variables
variable "create_node_security_group" {
  description = "Whether to create a security group for the EKS nodes"
  type        = bool
  default     = true
}

variable "security_group_use_name_prefix" {
  description = "Whether to use a name prefix for the security groups"
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
}

variable "cluster_security_group_id" {
  description = "Existing security group ID to use for the cluster"
  type        = string
  default     = ""
}

variable "node_security_group_id" {
  description = "Existing security group ID to use for the nodes"
  type        = string
  default     = ""
}

variable "maintain_default_security_group_rules" {
  description = "Whether to maintain the default security group rules"
  type        = bool
  default     = true
}

# Security Group Rule Type Definition
variable "security_rule" {
  description = "Type definition for security group rules"
  type = object({
    type                     = string
    protocol                 = string
    from_port                = number
    to_port                  = number
    description              = string
    cidr_blocks              = optional(list(string))
    source_security_group_id = optional(string)
    self                     = optional(bool)
  })
  default = null
}

variable "cluster_security_group_rules" {
  description = "Additional security group rules for the cluster"
  type = map(object({
    description              = string
    protocol                 = string
    from_port                = number
    to_port                  = number
    type                     = string
    cidr_blocks              = optional(list(string))
    source_security_group_id = optional(string)
    self                     = optional(bool)
  }))
  default = {}
}

variable "node_security_group_rules" {
  description = "Additional security group rules for the nodes"
  type = map(object({
    description              = string
    protocol                 = string
    from_port                = number
    to_port                  = number
    type                     = string
    cidr_blocks              = optional(list(string))
    source_security_group_id = optional(string)
    self                     = optional(bool)
  }))
  default = {}
}