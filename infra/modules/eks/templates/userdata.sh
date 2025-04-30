#!/bin/bash
set -o xtrace

# Install necessary packages
yum update -y
yum install -y amazon-ssm-agent
yum install -y jq

# Start SSM agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Configure kubelet
cat <<EOF > /etc/eks/bootstrap.sh
#!/bin/bash
set -o xtrace

# Set up the kubelet
/etc/eks/bootstrap.sh ${cluster_name} \
  --b64-cluster-ca ${cluster_auth_base64} \
  --apiserver-endpoint ${cluster_endpoint} \
  --use-max-pods false \
  --kubelet-extra-args '--node-labels=node.kubernetes.io/lifecycle=normal'
EOF

chmod +x /etc/eks/bootstrap.sh

# Run bootstrap script
/etc/eks/bootstrap.sh 