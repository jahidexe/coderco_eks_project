###############################################
# main.tf - EKS Cluster Module
###############################################

# EKS Cluster Role
resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.cluster_name}-cluster-role"
    }
  )
}

# Dynamic IAM policy attachments
resource "aws_iam_role_policy_attachment" "cluster_policies" {
  for_each   = toset(var.cluster_policies)
  policy_arn = each.value
  role       = aws_iam_role.cluster.name
}

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