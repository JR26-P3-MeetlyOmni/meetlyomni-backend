resource "aws_vpc" "meetlyomni-uat-vpc" {
  cidr_block       = var.vpc_cidr_block
  enable_dns_support = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.vpc_tag_name}-${var.environment}"
  }
}

### VPC Network Setup

# Create the private subnets
resource "aws_subnet" "private_subnets" {
  count                   = var.number_of_private_subnets
  vpc_id                  = aws_vpc.meetlyomni-uat-vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr_block, 4, count.index)
  availability_zone       = element(var.aws_availability_zones, count.index)
  map_public_ip_on_launch = false

  tags = {
    Name = "meetlyomni-private-subnet-${count.index + 1}-${var.environment}"
  }
}

# Create the public subnets
resource "aws_subnet" "public_subnets" {
  count                   = var.number_of_private_subnets
  vpc_id                  = aws_vpc.meetlyomni-uat-vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr_block, 4, count.index + 2)
  availability_zone       = element(var.aws_availability_zones, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name = "meetlyomni-public-subnet-${count.index + 1}-${var.environment}"
  }
}

### Security Group Setup
resource "aws_security_group" "meetlyomni-uat-sg" {
  name        = "${var.security_group_alb_name}-${var.environment}"
  description = "Security group for meetlyomni application"
  vpc_id      = aws_vpc.meetlyomni-uat-vpc.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Traffic to the ECS Cluster should only come from the ALB  
resource "aws_security_group" "ecs_tasks" {
  name        = "meetlyomni-ecs-tasks-sg-${var.environment}"
  description = "Security group for ECS tasks"
  vpc_id      = aws_vpc.meetlyomni-uat-vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.meetlyomni-uat-sg.id]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.meetlyomni-uat-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Internet Gateway for ALB
resource "aws_internet_gateway" "meetlyomni-igw" {
  vpc_id = aws_vpc.meetlyomni-uat-vpc.id

  tags = {
    Name = "meetlyomni-igw-${var.environment}"
  }
}

# Route table and subnet associations
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.meetlyomni-uat-vpc.id

  tags = {
    Name = "meetlyomni-private-rt-${var.environment}"
  }
}

# Public route table with internet gateway
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.meetlyomni-uat-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.meetlyomni-igw.id
  }

  tags = {
    Name = "meetlyomni-public-rt-${var.environment}"
  }
}

# Associate private route table with private subnets
resource "aws_route_table_association" "private_subnet_associations" {
  count          = var.number_of_private_subnets
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_rt.id
}

# Associate public route table with public subnets
resource "aws_route_table_association" "public_subnet_associations" {
  count          = var.number_of_private_subnets
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_rt.id
}

# Create NAT Gateway for ECR connectivity
resource "aws_eip" "nat" {
  domain = "vpc"
  
  tags = {
    Name = "meetlyomni-nat-eip-${var.environment}"
  }
}

resource "aws_nat_gateway" "meetlyomni-nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_subnets[0].id

  tags = {
    Name = "meetlyomni-nat-gateway-${var.environment}"
  }

  depends_on = [aws_internet_gateway.meetlyomni-igw]
}

# Add route to NAT Gateway in private route table
resource "aws_route" "private_nat_route" {
  route_table_id         = aws_route_table.private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.meetlyomni-nat.id
}
