# Pod Security Admission Controller
resource "kubernetes_config_map" "pod_security" {
  metadata {
    name      = "pod-security"
    namespace = "kube-system"
  }

  data = {
    "pod-security.yaml" = <<-EOT
    apiVersion: v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "restricted"
      enforce-version: "latest"
      audit: "restricted"
      audit-version: "latest"
      warn: "restricted"
      warn-version: "latest"
    exemptions:
      usernames: []
      runtimeClasses: []
      namespaces: ["kube-system"]
    EOT
  }
}

# Pod Security Standards
resource "kubernetes_namespace" "restricted" {
  metadata {
    name = "restricted"
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
    }
  }
}

# Default Network Policy (Deny All)
resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "default-deny"
    namespace = "default"
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# Security Context Constraints
resource "kubernetes_cluster_role" "restricted" {
  metadata {
    name = "restricted"
  }

  rule {
    api_groups = ["security.openshift.io"]
    resources  = ["securitycontextconstraints"]
    verbs      = ["use"]
    resource_names = ["restricted"]
  }
}

# Pod Security Context
resource "kubernetes_pod_security_policy" "restricted" {
  metadata {
    name = "restricted"
  }

  spec {
    privileged                 = false
    allow_privilege_escalation = false
    required_drop_capabilities = ["ALL"]
    volumes                    = ["configMap", "emptyDir", "projected", "secret", "downwardAPI", "persistentVolumeClaim"]

    host_network = false
    host_pid     = false
    host_ipc     = false

    run_as_user {
      rule = "MustRunAsNonRoot"
    }

    se_linux {
      rule = "RunAsAny"
    }

    supplemental_groups {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    fs_group {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }
  }
}

# Runtime Security Configuration
resource "kubernetes_config_map" "runtime_security" {
  metadata {
    name      = "runtime-security"
    namespace = "kube-system"
  }

  data = {
    "falco.yaml" = <<-EOT
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: falco-config
      namespace: kube-system
    data:
      falco.yaml: |
        file_output:
          enabled: true
          filename: /var/log/falco.log
        json_output: true
        json_include_output_property: true
        program_output:
          enabled: true
          keep_alive: false
          program: "jq '{timestamp: .time, rule: .rule, priority: .priority, output: .output}' | logger -t falco"
        syslog_output:
          enabled: true
        priority: debug
        rules_file:
          - /etc/falco/falco_rules.yaml
          - /etc/falco/falco_rules.local.yaml
          - /etc/falco/k8s_audit_rules.yaml
    EOT
  }
}

# Pod Security Context for Workloads
resource "kubernetes_pod" "example" {
  metadata {
    name      = "example"
    namespace = "restricted"
  }

  spec {
    security_context {
      run_as_non_root = true
      run_as_user     = 1000
      run_as_group    = 3000
      fs_group        = 2000
    }

    container {
      name  = "example"
      image = "nginx:latest"

      security_context {
        allow_privilege_escalation = false
        capabilities {
          drop = ["ALL"]
        }
        read_only_root_filesystem = true
      }

      resources {
        limits = {
          cpu    = "500m"
          memory = "512Mi"
        }
        requests = {
          cpu    = "250m"
          memory = "256Mi"
        }
      }
    }
  }
} 