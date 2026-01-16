terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

terraform {
  backend "s3" {
    bucket       = "tfstate-bucket-aarvika"
    key          = "env/dev/terraform.tfstate"
    region       = "us-east-2"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region
}

#--------------------------
# VPC + Subnets + Gateways
#--------------------------
resource "aws_vpc" "eks_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.cluster_name}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

# Public Subnets
resource "aws_subnet" "public_subnet_a" {
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = "10.0.101.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name                     = "${var.cluster_name}-public-a"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "public_subnet_b" {
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = "10.0.102.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true

  tags = {
    Name                     = "${var.cluster_name}-public-b"
    "kubernetes.io/role/elb" = "1"
  }
}

# Private Subnets
resource "aws_subnet" "private_subnet_a" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name                              = "${var.cluster_name}-private-a"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id            = aws_vpc.eks_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name                              = "${var.cluster_name}-private-b"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# NAT Gateway setup
resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet_a.id

  tags = {
    Name = "${var.cluster_name}-nat"
  }
}

# Route Tables
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.cluster_name}-public-rt"
  }
}

resource "aws_route_table_association" "public_a_assoc" {
  subnet_id      = aws_subnet.public_subnet_a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_b_assoc" {
  subnet_id      = aws_subnet.public_subnet_b.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "${var.cluster_name}-private-rt"
  }
}

resource "aws_route_table_association" "private_a_assoc" {
  subnet_id      = aws_subnet.private_subnet_a.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "private_b_assoc" {
  subnet_id      = aws_subnet.private_subnet_b.id
  route_table_id = aws_route_table.private_rt.id
}

data "aws_availability_zones" "available" {}

#--------------------------
# IAM Roles for EKS
#--------------------------
resource "aws_iam_role" "eks_cluster_role" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster_role.name
}

##--------------------------
#EKS Cluster
##--------------------------
resource "aws_eks_cluster" "eks_cluster" {
  name     = "vault-eks-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids = [
      aws_subnet.public_subnet_a.id,
      aws_subnet.public_subnet_b.id,
      aws_subnet.private_subnet_a.id,
      aws_subnet.private_subnet_b.id
    ]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller
  ]
}

#--------------------------
# Node Group IAM Role
#--------------------------
resource "aws_iam_role" "node_role" {
  name = "${var.cluster_name}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_role.name
}

resource "aws_iam_role_policy_attachment" "cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_role.name
}

resource "aws_iam_role_policy_attachment" "ecr_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_role.name
}

#--------------------------
# Node Group
#--------------------------
resource "aws_eks_node_group" "node_group" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "${var.cluster_name}-node-group"
  node_role_arn   = aws_iam_role.node_role.arn
  subnet_ids      = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["m7i-flex.large"]

  depends_on = [
    aws_iam_role_policy_attachment.worker_node_policy,
    aws_iam_role_policy_attachment.cni_policy,
    aws_iam_role_policy_attachment.ecr_policy
  ]

  tags = {
    Name = "${var.cluster_name}-nodegroup"
  }
}


variable "region" {
  default     = "us-east-2"
  description = "AWS region"
}

variable "cluster_name" {
  default     = "eks-manual"
  description = "EKS Cluster name"
}

variable "cluster_version" {
  default     = "1.30"
  description = "Kubernetes version"
}

# //
# variable "cluster_name" {
#   default = "vault-eks-cluster"
# }

# variable "namespace" {
#   default = "kube-system"
# }

# variable "service_account_name" {
#   default = "cluster-autoscaler"
# }

# variable "account_id" {
#   description = "AWS Account ID"
#   type        = string
# }

# #######################################
# Data sources
# #######################################

# data "aws_eks_cluster" "eks" {
#   name = var.cluster_name
# }

# data "aws_eks_cluster_auth" "eks" {
#   name = var.cluster_name
# }

# data "aws_iam_policy_document" "cluster_autoscaler_policy" {
#   statement {
#     effect = "Allow"

#     actions = [
#       "autoscaling:DescribeAutoScalingGroups",
#       "autoscaling:DescribeAutoScalingInstances",
#       "autoscaling:DescribeLaunchConfigurations",
#       "autoscaling:DescribeTags",
#       "autoscaling:SetDesiredCapacity",
#       "autoscaling:TerminateInstanceInAutoScalingGroup",
#       "ec2:DescribeLaunchTemplateVersions",
#       "ec2:DescribeInstanceTypes",
#       "ec2:DescribeInstances",
#     ]

#     resources = ["*"]
#   }
# }


# ######################################
# IAM Policy
# #######################################
# resource "aws_iam_policy" "cluster_autoscaler_policy" {
#   name        = "AmazonEKSClusterAutoscalerPolicy"
#   description = "IAM policy for EKS Cluster Autoscaler"
#   policy      = data.aws_iam_policy_document.cluster_autoscaler_policy.json
# }

# #######################################
# IAM Role for Service Account
# #######################################
# data "aws_iam_policy_document" "cluster_autoscaler_assume_role" {
#   statement {
#     effect = "Allow"

#     principals {
#       type        = "Federated"
#       identifiers = [
#         aws_iam_openid_connect_provider.eks.arn
#       ]
#     }

#     actions = ["sts:AssumeRoleWithWebIdentity"]

#     condition {
#       test     = "StringEquals"
#       variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
#       values   = ["system:serviceaccount:${var.namespace}:${var.service_account_name}"]
#     }
#   }
# }

# resource "aws_iam_role" "cluster_autoscaler_role" {
#   name               = "eks-cluster-autoscaler-role"
#   assume_role_policy = data.aws_iam_policy_document.cluster_autoscaler_assume_role.json
# }

# #######################################
# Attach Policy to Role
# #######################################
# resource "aws_iam_role_policy_attachment" "cluster_autoscaler_attach" {
#   role       = aws_iam_role.cluster_autoscaler_role.name
#   policy_arn = aws_iam_policy.cluster_autoscaler_policy.arn
# }

# #######################################
# EKS OIDC Provider
# #######################################
# resource "aws_iam_openid_connect_provider" "eks" {
#   url             = data.aws_eks_cluster.eks.identity[0].oidc[0].issuer
#   client_id_list  = ["sts.amazonaws.com"]
#   thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0ecd4e4c3"] #Default for AWS OIDC
# }

# #######################################
# Kubernetes Service Account
# #######################################
# resource "kubernetes_service_account" "cluster_autoscaler_sa" {
#   metadata {
#     name      = var.service_account_name
#     namespace = var.namespace
#     annotations = {
#       "eks.amazonaws.com/role-arn" = aws_iam_role.cluster_autoscaler_role.arn
#     }
#   }

#   depends_on = [aws_iam_role.cluster_autoscaler_role]
# }


# resource "aws_security_group" "web_sg" {
#   name        = "web-security-group"
#   description = "Security group for web servers"
#   vpc_id      = "vpc-0b863cdfc8e5475e7"

#   tags = {
#     Name = "web-security-group"
#   }
# }

# import {
#   to = aws_security_group.web_sg
#   id = "sg-03086a6e0b3833984"
# }



