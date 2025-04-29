#!/bin/bash
set -o xtrace

# Install security updates
yum update -y --security

# Install and configure SSM agent
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Configure kubelet security settings
cat <<EOF > /etc/sysctl.d/99-kubernetes.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sysctl --system

# Configure kubelet with security settings
cat <<EOF > /etc/kubernetes/kubelet/kubelet-config.json
{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "authentication": {
    "anonymous": {
      "enabled": false
    }
  },
  "authorization": {
    "mode": "Webhook"
  },
  "serverTLSBootstrap": true,
  "protectKernelDefaults": true,
  "readOnlyPort": 0,
  "eventRecordQPS": 0,
  "streamingConnectionIdleTimeout": "4h0m0s",
  "makeIPTablesUtilChains": true,
  "featureGates": {
    "RotateKubeletServerCertificate": true
  }
}
EOF

# Bootstrap node
/etc/eks/bootstrap.sh ${cluster_name} \
  --b64-cluster-ca ${cluster_ca} \
  --apiserver-endpoint ${cluster_endpoint} \
  ${bootstrap_extra_args}

# Enable and start kubelet
systemctl enable kubelet
systemctl start kubelet 