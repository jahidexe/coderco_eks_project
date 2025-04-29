###############################################
# node_groups.tf - EKS Node Groups and Fargate Profiles
###############################################

# Node Group IAM Role
resource "aws_iam_role" "node_group" {
  for_each = var.managed_node_groups

  name = "${var.cluster_name}-${each.key}-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-${each.key}-node-group-role"
    }
  )
}

# Node Group IAM Policy Attachments
resource "aws_iam_role_policy_attachment" "node_group_policies" {
  for_each = var.managed_node_groups

  role       = aws_iam_role.node_group[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_group_cni_policies" {
  for_each = var.managed_node_groups

  role       = aws_iam_role.node_group[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_group_ecr_policies" {
  for_each = var.managed_node_groups

  role       = aws_iam_role.node_group[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Managed Node Groups
resource "aws_eks_node_group" "this" {
  for_each = var.managed_node_groups

  cluster_name    = aws_eks_cluster.this.name
  node_group_name = each.value.name
  node_role_arn   = aws_iam_role.node_group[each.key].arn
  subnet_ids      = var.subnet_ids

  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  launch_template {
    id      = aws_launch_template.node_group[each.key].id
    version = aws_launch_template.node_group[each.key].latest_version
  }

  capacity_type  = each.value.capacity_type
  ami_type       = each.value.ami_type
  disk_size      = each.value.disk_size

  labels = merge(
    each.value.labels,
    {
      "node.kubernetes.io/instance-type" = each.value.instance_types[0]
    }
  )

  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  update_config {
    max_unavailable_percentage = each.value.update_config.max_unavailable_percentage
  }

  # Enable node auto-repair
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.tags,
    each.value.tags,
    {
      Name = "${var.cluster_name}-${each.key}-node-group"
    }
  )
}

# Launch Template for Node Groups
resource "aws_launch_template" "node_group" {
  for_each = var.managed_node_groups

  name_prefix   = "${var.cluster_name}-${each.key}-"
  image_id      = data.aws_ami.eks_optimized[each.key].id
  instance_type = each.value.instance_types[0]
  user_data     = base64encode(templatefile("${path.module}/templates/userdata.sh", {
    cluster_name        = var.cluster_name
    cluster_endpoint    = aws_eks_cluster.this.endpoint
    cluster_auth_base64 = aws_eks_cluster.this.certificate_authority[0].data
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(
      var.tags,
      each.value.tags,
      {
        Name = "${var.cluster_name}-${each.key}-node"
      }
    )
  }

  tags = merge(
    var.tags,
    each.value.tags,
    {
      Name = "${var.cluster_name}-${each.key}-launch-template"
    }
  )
}

# EKS Optimized AMI
data "aws_ami" "eks_optimized" {
  for_each = var.managed_node_groups

  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.kubernetes_version}-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Fargate Profile
resource "aws_eks_fargate_profile" "this" {
  for_each = var.fargate_profiles

  cluster_name           = aws_eks_cluster.this.name
  fargate_profile_name   = each.value.name
  pod_execution_role_arn = aws_iam_role.fargate[each.key].arn
  subnet_ids            = var.subnet_ids

  selector {
    namespace = each.value.namespace
    labels    = each.value.labels
  }

  tags = merge(
    var.tags,
    each.value.tags,
    {
      Name = "${var.cluster_name}-${each.key}-fargate-profile"
    }
  )
}

# Fargate IAM Role
resource "aws_iam_role" "fargate" {
  for_each = var.fargate_profiles

  name = "${var.cluster_name}-${each.key}-fargate-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks-fargate-pods.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    each.value.tags,
    {
      Name = "${var.cluster_name}-${each.key}-fargate-role"
    }
  )
}

# Fargate IAM Policy Attachments
resource "aws_iam_role_policy_attachment" "fargate_policies" {
  for_each = var.fargate_profiles

  role       = aws_iam_role.fargate[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}