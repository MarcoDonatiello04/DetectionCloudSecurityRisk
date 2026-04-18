provider "aws" {
  region = "eu-west-1"
}

# ---------------------------
# VPC
# ---------------------------
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

# ---------------------------
# Subnet pubblica
# ---------------------------
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

# ---------------------------
# Internet Gateway
# ---------------------------
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

# ---------------------------
# Route Table
# ---------------------------
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "internet_access" {
  route_table_id         = aws_route_table.public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}

# ---------------------------
# Security Group (con problemi)
# ---------------------------
resource "aws_security_group" "web_sg" {
  name   = "web_sg"
  vpc_id = aws_vpc.main.id

  # SSH aperto a tutti ❌
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP pubblico ✔️
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # RDP aperto ❌
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # uscita libera
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------
# Istanza EC2
# ---------------------------
resource "aws_instance" "web" {
  ami                    = "ami-12345678"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  tags = {
    Name = "WebServer"
  }
}

# ---------------------------
# Variabili
# ---------------------------
variable "instance_name" {
  type    = string
  default = "example-instance"
}

# ---------------------------
# Output
# ---------------------------
output "instance_id" {
  value = aws_instance.web.id
}