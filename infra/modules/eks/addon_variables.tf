###############################################
# addon_variables.tf - EKS Add-on Variables
###############################################

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

variable "enable_ebs_csi_driver" {
  description = "Enable EBS CSI Driver add-on"
  type        = bool
  default     = true
}

variable "addon_version_preferences" {
  description = "Version preferences for EKS add-ons"
  type = object({
    vpc_cni   = string
    coredns   = string
    kube_proxy = string
    ebs_csi   = string
  })
  default = {
    vpc_cni   = "latest"
    coredns   = "latest"
    kube_proxy = "latest"
    ebs_csi   = "latest"
  }
}

variable "addon_configurations" {
  description = "Configuration values for EKS add-ons"
  type = object({
    vpc_cni = map(string)
    coredns = map(string)
    kube_proxy = map(string)
    ebs_csi = map(string)
  })
  default = {
    vpc_cni   = {}
    coredns   = {}
    kube_proxy = {}
    ebs_csi   = {}
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